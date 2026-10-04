.. SPDX-License-Identifier: GPL-2.0

========================
mxl862xx devlink support
========================

This document describes the devlink features implemented by the
``mxl862xx`` device driver.

Info versions
=============

The ``mxl862xx`` driver reports the following versions

.. list-table:: devlink info versions implemented
   :widths: 5 5 5 85

   * - Name
     - Type
     - Example
     - Description
   * - ``asic.id``
     - fixed
     - 8628
     - The chip part number read from the CHIP ID registers. Omitted
       when the part number reads as zero, which happens for a switch
       sitting in MCUboot rescue mode (the registers need a running
       firmware), when the read fails on a running firmware, for an
       unfused part, and after a failed flash.
   * - ``asic.rev``
     - fixed
     - 0
     - The chip version, read from the CHIP ID registers as well. Both
       values are published behind the same check, so it is omitted
       whenever ``asic.id`` is.
   * - ``fw``
     - running, stored
     - 1.0.70
     - Version of the firmware running on the switch, reported as both
       running and stored since the switch boots it from its own flash.
       It is omitted while no firmware version is known: after a failed
       flash until the reprobe it schedules, and in MCUboot rescue mode
       while an interrupted download is still being recovered in the
       background, once that recovery has failed, or while the loader
       waits in an opening handshake nobody can finish. Once the loader
       is ready to accept a new image the version appears as "0.0.0",
       which no released firmware reports, so version-comparing tools
       offer any available release as an upgrade; it is reported as
       running only, since the driver cannot tell what the flash holds
       while the loader runs. A missing version on its own does not say
       why; ``devlink dev flash``, given an image file that passes the
       driver's validation, answers ``-EBUSY`` while the switch is still
       recovering and ``-EIO`` once it cannot be flashed from this
       binding, see below.

Flash Update
============

The ``mxl862xx`` driver implements support for ``devlink dev flash``.
The driver checks the image file's header and payload checksums before
touching the switch and refuses a file that fails them. The image is
then transferred to the switch over the same MDIO bus which is also
used to manage the switch, checked for integrity again and installed
by the MCUboot bootloader running on the switch. All ports of the
switch are closed and held closed for the duration of the update, the
conduit interface is closed with them, and the driver reprobes the
switch after it has rebooted into the new firmware. The reprobe
destroys and recreates the user ports, so their bridge membership,
VLANs, addresses and every other per-port configuration are lost with
them; they come back registered but down, and userspace configures and
brings them up again, which opens the conduit with them. A complete
flash and reprobe cycle takes on the order of a minute, depending on
the board's flash chip. Until the reprobe has run, a further update is
refused with ``-EBUSY``, as is one requested before the switch has
finished setting up. In the rare case that the reprobe cannot be
scheduled at all, the kernel log says so, ``devlink dev flash`` reports
that error or the transfer's own if the transfer failed as well, and
the driver stays bound to a switch it no longer tracks, with its ports
unusable and further updates refused with ``-EBUSY``, until it is
unbound and rebound. A reboot started while an update is running waits
for the transfer to finish, and an update requested after the system
has begun shutting down is refused with ``-ENODEV``.

A switch stuck in MCUboot rescue mode, e.g. after an interrupted
update, is registered without user ports. A loader found in its
flashless download loop, or one that does not service its mailbox, is
not usable from here and fails probe; the kernel log reports the
state's errno, ``-EOPNOTSUPP`` for the flashless loop and ``-ENXIO``
for the unserviced mailbox. If the previous download was interrupted
mid-transfer the loader is wedged; the driver drains it back to a clean
ready state in the background, one byte at a time, which takes tens of
minutes for a large image and is reported through the kernel log as it
progresses. During that recovery ``devlink dev flash`` returns
``-EBUSY`` with an extack message saying so, and ``devlink dev info``
reports no firmware version. Once the loader is ready the firmware
version appears and flashing a firmware image through the regular
update flow recovers the switch.

If the switch cannot be flashed from its binding, ``devlink dev flash``
returns ``-EIO`` and says so in its extack message; the kernel log
reports why, naming a loader that stopped answering, a drain that
reached its bound or a reprobe that could not be scheduled where that
is the cause and the bus error otherwise. The drain runs once and is
never resumed, so a failed MDIO transaction ends it as well. A loader
that stops answering the drain, one still busy once the erase of the
interrupted session should long have finished, and a drain that
reaches its bound without the loader returning to its ready state need
a power cycle; a completed drain whose reprobe could not be scheduled,
and a drain a bus error cut short, need only a driver rebind. The
driver re-examines the switch
when it binds and at no other time, so a power cycle on a board where
the switch can be cycled on its own still has to be followed by an
unbind and rebind for the recovered switch to be recognised.

A download interrupted during its opening handshake, before the image
header reached the loader, is reported the same way. The driver starts
a download only from the loader's ready state and does not resume that
session, so the switch needs a power cycle.
