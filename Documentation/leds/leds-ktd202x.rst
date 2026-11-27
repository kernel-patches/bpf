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

All LEDs of a chip blink and breathe with one flash timer. Several LEDs can
use it at once only with the same period, on time and ramps. A LED that asks
for different ones while another LED is on the timer gets -EBUSY: blinking
then falls back to the software timer, and ``hw_pattern`` returns the error
and leaves the LED as it was.

The match is on the values programmed into the chip. The timer trigger sets
``delay_on`` and ``delay_off`` one at a time and the driver rounds each pair,
so two LEDs given the same delays can end up with slightly different on times,
and then the second one blinks in software. To share the timer, give the
second LED the delays that the first one reads back. Only at the 128 ms
ET6326 period, where a millisecond is two steps of the on time, can an odd
on time still come out one step off.

For example, to breathe with a period of 4 seconds::

    echo pattern > /sys/class/leds/blue:status/trigger
    echo "0 1000 192 1000 192 1000 0 1000" > /sys/class/leds/blue:status/hw_pattern
