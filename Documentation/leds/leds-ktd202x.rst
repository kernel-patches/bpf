.. SPDX-License-Identifier: GPL-2.0-only

=============================================
Kinetic KTD2026/7 and Etek ET6326 LED driver
=============================================

The chips have a hardware timer that blinks or breathes the LEDs without the
CPU. The timer trigger uses it for blinking, and the pattern trigger uses it
for breathing through the ``hw_pattern`` file.

The hardware pattern is one breathing cycle of four steps, which repeats
forever::

    "0 rise brightness high brightness fall 0 low"

rise
    Ramp-up time in ms, from 0 to 1920 in steps of 128 ms.

high
    Time spent at the brightness in ms.

fall
    Ramp-down time in ms, from 0 to 1920 in steps of 128 ms.

low
    Time spent off in ms.

The first and the last brightness must be 0, and the two in the middle must be
equal and not 0. ``repeat`` must be -1, its default.

The sum of the four times is the flash period. The driver rounds it up to the
next step of 128 ms, between 256 ms (128 ms on the ET6326) and 16384 ms.

The flash period, the on time and the ramp times are shared by all LEDs of a
chip. When several LEDs blink or breathe at once, they all follow the timing
that was set last.

For example, to breathe with a period of 4 seconds::

    echo pattern > /sys/class/leds/blue:status/trigger
    echo "0 1000 192 1000 192 1000 0 1000" > /sys/class/leds/blue:status/hw_pattern
