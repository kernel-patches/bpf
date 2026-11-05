.. SPDX-License-Identifier: GPL-2.0

============================
PCI Peer-to-Peer DMA Support
============================

The PCI bus has pretty decent support for performing DMA transfers
between two devices on the bus. This type of transaction is henceforth
called Peer-to-Peer (or P2P). However, there are a number of issues that
make P2P transactions tricky to do in a perfectly safe way.

For PCIe the routing of Transaction Layer Packets (TLPs) is well-defined up
until they reach a host bridge or root port. If the path includes PCIe switches
then based on the ACS settings the transaction can route entirely within
the PCIe hierarchy and never reach the root port. The kernel will evaluate
the PCIe topology and always permit P2P in these well-defined cases.

The client is the PCIe Requester and the provider is the Completer, whether
the client reads or writes provider memory. For devices on separate links
below the same Root Port, their paths first meet in a Switch, where they
diverge.
A Request enters that Switch through the Downstream Port above the
Requester, the Requester-side port. If ACS P2P Request Redirect is enabled
there, the Request is routed upstream; otherwise it is routed back
downstream through the Downstream Port leading to the Completer, the
Completer-side port. The path of Completions from a read likewise depends on
ACS P2P Completion Redirect in the Completer-side port. An enabled Egress
Control is conservatively treated as a Request redirect.

Below the divergence, the route toward the other branch is already upstream,
so those P2P redirect controls do not affect it. Redirect controls for the
reverse transaction directions do not affect the mapping. P2P DMA is routed
through the host bridge when either applicable port redirects. If an ACS
Control register needed for a route cannot be read, that route is rejected.

Functions sharing one PCIe link can instead route internally within their
device. An ACS capability without Request or Completion Redirect support
means that the corresponding internal route does not exist. Device-specific
ACS quirks can report the same restriction for functions without ACS, and
SR-IOV functions without ACS cannot support internal peer traffic. These
restrictions apply only between functions sharing the link, including ARI
functions and VFs; they do not redirect traffic to a separate device.

When traffic continues upstream beyond the divergence, ACS Upstream Forwarding
must be enabled, or provided by a device-specific quirk, at every shared
Downstream and Root Port on the way to the host bridge. This includes ports
above a shared Switch Upstream Port as well as ports shared by sibling
functions. Missing forwarding support or unreadable forwarding controls reject
the host route while leaving direct routes available. The host bridge must
also support P2P. Clearing redirect controls cannot create an internal route
that the device does not support.

Three of those controls act on TLP attributes that the Requester chooses rather
than on the topology, so the same path routes differently for different
traffic. ACS Translation Blocking rejects any upstream Request whose Address
Type is not Untranslated, and takes precedence over every other P2P control.
ACS Direct Translated P2P routes a Translated Request to the peer regardless of
Request Redirect and Egress Control. ACS Completion Redirect leaves alone
Completions that carry the Relaxed Ordering attribute, which a Completion
copies from the Request it answers.

P2PDMA therefore decides each class of traffic separately, and
``pci_p2pdma_map_type()`` answers for the one a DMA mapping is built for:
strictly ordered Requests carrying an Untranslated address.

The two directions are decided independently. Translation Blocking (TB),
Direct Translated P2P (DT), Request Redirect (RR) and Egress Control (EC) on
the Requester-side port decide the Request:

=====  =====  =======  ============  ==========
TB     DT     RR/EC    TLP class     Request
=====  =====  =======  ============  ==========
set    x      x        translated    blocked
clear  set    x        translated    direct
clear  clear  clear    translated    direct
clear  clear  set      translated    redirected
x      x      clear    untranslated  direct
x      x      set      untranslated  redirected
=====  =====  =======  ============  ==========

Completion Redirect (CR) on the Completer-side port decides the Completions:

=====  =========  ==========
CR     TLP class  Completion
=====  =========  ==========
x      relaxed    direct
clear  strict     direct
set    strict     redirected
=====  =========  ==========

Combining the two tables gives the mapping type. A class is bus addressable
when its Request and its Completions both route directly, and anything else
goes through the host bridge. A blocked Request has neither route, because
Translation Blocking rejects the Address Type itself rather than the
destination. With no ACS control set anywhere, every class routes directly
provided that any required internal route between sibling functions exists.
Neither Direct Translated P2P nor Relaxed Ordering can create such a route.

Some ports without an ACS capability, such as certain Zhaoxin Switch
Downstream Ports, redirect peer-to-peer traffic anyway, and a device-specific
ACS quirk tells the kernel so. P2PDMA treats such a port as having Request and
Completion Redirect set, but with no exception for Relaxed Ordering, so it
redirects every Completion.

Note that DT only matters where RR or EC would otherwise redirect: it
overrides them for a Translated address rather than granting a direct route
that was not already there.

Translation Blocking is not a routing control, so it is evaluated on every
port the Request passes on its way upstream rather than at the divergence
alone. A direct route turns around at the divergence and only passes the ports
below it, while the host bridge route keeps climbing and passes that port and
everything above it as well. Neither route falls back to the other, because
the Address Type is rejected wherever the Request is addressed.

However, if the P2P transaction reaches the host bridge then it might have to
hairpin back out the same root port, be routed inside the CPU SOC to another
PCIe root port, or routed internally to the SOC.

The PCIe specification doesn't define the forwarding of transactions between
hierarchy domains and kernel defaults to blocking such routing. There is an
allow list to allow detecting known-good HW, in which case P2P between any
two PCIe devices will be permitted.

Since P2P inherently is doing transactions between two devices it requires two
drivers to be co-operating inside the kernel. The providing driver has to convey
its MMIO to the consuming driver. To meet the driver model lifecycle rules the
MMIO must have all DMA mapping removed, all CPU accesses prevented, all page
table mappings undone before the providing driver completes remove().

This requires the providing and consuming driver to actively work together to
guarantee that the consuming driver has stopped using the MMIO during a removal
cycle. This is done by either a synchronous invalidation shutdown or waiting
for all usage refcounts to reach zero.

At the lowest level the P2P subsystem offers a naked struct p2p_provider that
delegates lifecycle management to the providing driver. It is expected that
drivers using this option will wrap their MMIO memory in DMABUF and use DMABUF
to provide an invalidation shutdown. These MMIO addresses have no struct page, and
if used with mmap() must create special PTEs. As such there are very few
kernel uAPIs that can accept pointers to them; in particular they cannot be used
with read()/write(), including O_DIRECT.

Building on this, the subsystem offers a layer to wrap the MMIO in a ZONE_DEVICE
pgmap of MEMORY_DEVICE_PCI_P2PDMA to create struct pages. The lifecycle of
pgmap ensures that when the pgmap is destroyed all other drivers have stopped
using the MMIO. This option works with O_DIRECT flows, in some cases, if the
underlying subsystem supports handling MEMORY_DEVICE_PCI_P2PDMA through
FOLL_PCI_P2PDMA. The use of FOLL_LONGTERM is prevented. As this relies on pgmap
it also relies on architecture support along with alignment and minimum size
limitations.


Driver Writer's Guide
=====================

In a given P2P implementation there may be three or more different
types of kernel drivers in play:

* Provider - A driver which provides or publishes P2P resources like
  memory or doorbell registers to other drivers.
* Client - A driver which makes use of a resource by setting up a
  DMA transaction to or from it.
* Orchestrator - A driver which orchestrates the flow of data between
  clients and providers.

In many cases there could be overlap between these three types (i.e.,
it may be typical for a driver to be both a provider and a client).

For example, in the NVMe Target Copy Offload implementation:

* The NVMe PCI driver is both a client, provider and orchestrator
  in that it exposes any CMB (Controller Memory Buffer) as a P2P memory
  resource (provider), it accepts P2P memory pages as buffers in requests
  to be used directly (client) and it can also make use of the CMB as
  submission queue entries (orchestrator).
* The RDMA driver is a client in this arrangement so that an RNIC
  can DMA directly to the memory exposed by the NVMe device.
* The NVMe Target driver (nvmet) can orchestrate the data from the RNIC
  to the P2P memory (CMB) and then to the NVMe device (and vice versa).

This is currently the only arrangement supported by the kernel but
one could imagine slight tweaks to this that would allow for the same
functionality. For example, if a specific RNIC added a BAR with some
memory behind it, its driver could add support as a P2P provider and
then the NVMe Target could use the RNIC's memory instead of the CMB
in cases where the NVMe cards in use do not have CMB support.


Provider Drivers
----------------

A provider simply needs to register a BAR (or a portion of a BAR)
as a P2P DMA resource using :c:func:`pci_p2pdma_add_resource()`.
This will register struct pages for all the specified memory.

After that it may optionally publish all of its resources as
P2P memory using :c:func:`pci_p2pmem_publish()`. This will allow
any orchestrator drivers to find and use the memory. When marked in
this way, the resource must be regular memory with no side effects.

For the time being this is fairly rudimentary in that all resources
are typically going to be P2P memory. Future work will likely expand
this to include other types of resources like doorbells.


Client Drivers
--------------

A client driver only has to use the mapping API :c:func:`dma_map_sg()`
and :c:func:`dma_unmap_sg()` functions as usual, and the implementation
will do the right thing for the P2P capable memory.


Orchestrator Drivers
--------------------

The first task an orchestrator driver must do is compile a list of
all client devices that will be involved in a given transaction. For
example, the NVMe Target driver creates a list including the namespace
block device and the RNIC in use. If the orchestrator has access to
a specific P2P provider to use it may check compatibility using
:c:func:`pci_p2pdma_distance()` otherwise it may find a memory provider
that's compatible with all clients using  :c:func:`pci_p2pmem_find()`.
If more than one provider is supported, the one nearest to all the clients will
be chosen first. If more than one provider is an equal distance away, the
one returned will be chosen at random (it is not an arbitrary but
truly random). This function returns the PCI device to use for the provider
with a reference taken and therefore when it's no longer needed it should be
returned with pci_dev_put().

Once a provider is selected, the orchestrator can then use
:c:func:`pci_alloc_p2pmem()` and :c:func:`pci_free_p2pmem()` to
allocate P2P memory from the provider. :c:func:`pci_p2pmem_alloc_sgl()`
and :c:func:`pci_p2pmem_free_sgl()` are convenience functions for
allocating scatter-gather lists with P2P memory.

Struct Page Caveats
-------------------

While the MEMORY_DEVICE_PCI_P2PDMA pages can be installed in VMAs,
pin_user_pages() and related will not return them unless FOLL_PCI_P2PDMA is set.

The MEMORY_DEVICE_PCI_P2PDMA pages require care to support in the kernel. The
KVA is still MMIO and must still be accessed through the normal
readX()/writeX()/etc helpers. Direct CPU access (e.g. memcpy) is forbidden, just
like any other MMIO mapping. While this will actually work on some
architectures, others will experience corruption or just crash in the kernel.
Supporting FOLL_PCI_P2PDMA in a subsystem requires scrubbing it to ensure no CPU
access happens.


Usage With DMABUF
=================

DMABUF provides an alternative to the above struct page-based
client/provider/orchestrator system and should be used when struct page
doesn't exist. In this mode the exporting driver will wrap
some of its MMIO in a DMABUF and give the DMABUF FD to userspace.

Userspace can then pass the FD to an importing driver which will ask the
exporting driver to map it to the importer.

In this case the initiator and target pci_devices are known and the P2P subsystem
is used to determine the mapping type. The phys_addr_t-based DMA API is used to
establish the dma_addr_t.

Lifecycle is controlled by DMABUF revocation. When the exporting driver wants
to remove() it must deliver an invalidation shutdown to all DMABUF importing
drivers through dma_buf_invalidate_mappings() and synchronously DMA unmap all
the MMIO. Importers unable to complete that unmap within bounded time have to
be rejected when they attach, which dma_buf_attach_revocable() checks for.

No importing driver can continue to have a DMA map to the MMIO after the
exporting driver has destroyed its p2p_provider.


P2P DMA Support Library
=======================

.. kernel-doc:: drivers/pci/p2pdma.c
   :export:
