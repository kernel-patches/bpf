.. SPDX-License-Identifier: GPL-2.0

========================
ptp_ocp devlink support
========================

This document describes the devlink features implemented by the ``ptp_ocp``
device driver: the info versions it reports and its flash update support.

Info versions
=============

The ``ptp_ocp`` driver reports the following versions

.. list-table:: devlink info versions implemented
   :widths: 5 5 90

   * - Name
     - Type
     - Description
   * - ``fw``
     - running
     - Version of the firmware running on the card.  Reported as ``loader``
       instead when the card is running the firmware loader.
   * - ``board.id``
     - fixed
     - Board identifier, read from the on-card EEPROM.
   * - ``cpld.id``
     - fixed
     - Lattice device ID (IDCODE) of the TAP CPLD, formatted as ``0x%08x``.
       Only present on ADVA TimeCard X1 boards, which are the only ones
       carrying that CPLD.  Reading it claims the shared I2C bus and
       reprograms the on-card mux, so the driver does that from its own
       worker and reports the cached value here; the version is omitted
       until that read has succeeded.  The read is made once per binding
       and again after a successful CPLD update.
   * - ``fw.cpld``
     - running
     - USERCODE of the image programmed into the TAP CPLD, formatted as
       ``0x%08x``.  Read together with ``cpld.id`` and reported the same
       way.  This is the component name to pass to ``devlink dev flash``
       to update the CPLD.

Flash update
============

The driver implements ``devlink dev flash`` for two separate targets,
selected with the component name.

.. list-table:: Flash components
   :widths: 20 80

   * - Component
     - Description
   * - (none)
     - The card's own flash, written through the SPI controller the driver
       exposes. Not supported on WiWi. The card runs the new image after
       its next reset.
   * - ``fw.cpld``
     - The configuration flash of the TAP CPLD on ADVA TimeCard X1 boards,
       programmed over I2C with the MachXO3 in-system programming commands
       and activated with a REFRESH, so the new image runs immediately.
       The image is the raw configuration bitstream.  The only check the
       driver makes is that its length is a non-zero multiple of the
       16-byte page size, so a container such as ``.jed`` has to be
       converted first rather than passed through - one whose length
       happens to be a multiple of 16 would be programmed as if it were
       a bitstream.

Programming the CPLD claims the shared I2C bus for the whole cycle, so
reads of the card's EEPROM block until it completes.  Progress is reported
with the standard devlink status notifications.

Example::

    $ devlink dev flash pci/0000:02:00.0 file adva-cpld.bin component fw.cpld

WiWi production firmware
========================

WiWi Time Cards with PCI ID ``2163:1008`` and subsystem ID ``10ee:0007``
use the PCI Revision ID to identify the register interface. The driver
supports revision ``02`` (LitePCIe/MSI-X) and rejects unknown revisions
before accessing FPGA registers. Incompatible interface changes require
a new revision. The driver also checks the BAR and MSI-X layout before
initializing the card.

The image ID at BAR0 offset ``0x02020000`` identifies a firmware build,
not the register interface. The running ``fw`` version in devlink reports
the full image ID, for example ``0x0000800f``. Compatible builds need not
have the same image ID or individual core versions. PCIe access to the
CoreList is not required.

The image uses the Celestica LitePCIe production map: add ``0x02000000``
to the peripheral offsets and use aligned 32-bit MMIO. Interrupt input
``n`` uses MSI-X vector ``n + 32``. The per-input enable mask is at BAR0
offset ``0x1800``. The driver enables the SPI interrupt before probing
the flash and defers timing interrupts until the PHC is ready. GNSS2 is
not wired to pins on the tested image; no second GNSS port is registered.
The separate EEPROM and RGB I2C inputs (17 and 18) have no handlers in
this driver and stay masked; these are distinct from its I2C input 7.

WiWi firmware updates through ``devlink dev flash`` are not supported.
The WiWi image has a different flash header from the Celestica image.
The golden image at flash offset zero boots the update image via MultiBoot
with watchdog fallback. The vendor's programming path requires a modified
``spi-xilinx`` driver. Recognizing the SPI NOR does not validate that path
or the image header. Successful clock registration does not establish
GNSS synchronization or valid UTC.
