.. SPDX-License-Identifier: GPL-2.0

==========================
DPLL simulator (dpllsim)
==========================

The dpllsim driver provides simulated DPLL devices for testing the DPLL
subsystem and its userspace tooling without real hardware, similar to
what netdevsim provides for network devices.

Configuration interface
=======================

Devices are described in configfs under ``/sys/kernel/config/dpllsim/``.
A directory created there is a device instance. Attributes are written
while the instance is not live, then ``live`` is set to 1 to register
the device with the DPLL subsystem. Writing 0 unregisters it again.
Structural attributes return ``EBUSY`` while the instance is live.

Device directory ``/sys/kernel/config/dpllsim/<dev>/``:

=======================  =====================================================
``clock_id``             Clock ID of the DPLL device, must be nonzero and
                         unique among live instances
``live``                 1 registers the device, 0 unregisters it
=======================  =====================================================

Example
=======

Create a device and make it live::

    cd /sys/kernel/config/dpllsim
    mkdir dev0 && cd dev0
    echo 100 > clock_id
    echo 1 > live

    dpll device show

To remove the device, write 0 to ``live`` and remove the device
directory.
