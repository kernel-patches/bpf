.. SPDX-License-Identifier: GPL-2.0

==============================
Kernel subsystem documentation
==============================

These books get into the details of how specific kernel subsystems work
from the point of view of a kernel developer.  Much of the information here
is taken directly from the kernel source, with supplemental material added
as needed (or at least as we managed to add it — probably *not* all that is
needed).

Core subsystems
---------------

.. toctree::
   :maxdepth: 1

   core-api/index
   driver-api/index
   mm/index
   power/index
   scheduler/index
   timers/index
   locking/index

Bus and Communication interfaces
--------------------------------

.. toctree::
   :maxdepth: 1

   i2c/index
   pcmcia/index
   spi/index
   w1/index
   usb/index
   PCI/index
   peci/index

Human interfaces
----------------

.. toctree::
   :maxdepth: 1

   input/index
   hid/index
   sound/index
   gpu/index
   fb/index
   leds/index

Networking interfaces
---------------------

.. toctree::
   :maxdepth: 1

   networking/index
   netlabel/index
   infiniband/index
   mhi/index

Storage interfaces
------------------

.. toctree::
   :maxdepth: 1

   filesystems/index
   block/index
   cdrom/index
   scsi/index
   target/index
   nvme/index

Other subsystems
----------------
**Fixme**: much more organizational work is needed here.

.. toctree::
   :maxdepth: 1

   accounting/index
   cpu-freq/index
   edac/index
   fpga/index
   iio/index
   watchdog/index
   virt/index
   hwmon/index
   accel/index
   security/index
   crypto/index
   bpf/index
   misc-devices/index
   wmi/index
   tee/index
