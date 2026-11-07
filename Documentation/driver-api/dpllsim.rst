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
A directory created there is a device instance, a directory created in
its ``pins/`` subdirectory is a pin. Attributes are written while the
instance is not live, then ``live`` is set to 1 to register the device
and its pins with the DPLL subsystem. Writing 0 unregisters everything
again. Structural attributes return ``EBUSY`` while the instance is live
and pins of a live instance cannot be removed.

Device directory ``/sys/kernel/config/dpllsim/<dev>/``:

=======================  =====================================================
``clock_id``             Clock ID of the DPLL device, must be nonzero and
                         unique among live instances
``live``                 1 registers the device, 0 unregisters it
=======================  =====================================================

Pin directory ``/sys/kernel/config/dpllsim/<dev>/pins/<pin>/``:

=============  ===============================================================
``type``       ``gnss``, ``int-oscillator``, ``ext``, ``synce-eth-port`` or
               ``mux`` (default ``ext``)
``frequency``  Frequency in Hz, must be supported by the pin type
               (default 0, which is rejected)
``direction``  ``input`` or ``output`` (default ``input``), a ``mux`` pin
               must be an input
``prio``       Priority 0-255 used for automatic reference selection,
               input pins only, output pins must keep the default
               (default 128)
=============  ===============================================================

The pin directory name becomes the board label of the pin. Pins are
registered in the order the directories were created.

Example
=======

Create a device with a GNSS input, an external input and an external
output, then make it live::

    cd /sys/kernel/config/dpllsim
    mkdir dev0 && cd dev0
    echo 100 > clock_id
    mkdir pins/gnss0
    echo gnss > pins/gnss0/type
    echo 1 > pins/gnss0/frequency
    echo 0 > pins/gnss0/prio
    mkdir pins/ext0
    echo 10000000 > pins/ext0/frequency
    echo 1 > pins/ext0/prio
    mkdir pins/out0
    echo 10000000 > pins/out0/frequency
    echo output > pins/out0/direction
    echo 1 > live

    dpll device show
    dpll pin show

To remove the device, write 0 to ``live``, remove the pin directories
and finally the device directory.
