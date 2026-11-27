# SPDX-License-Identifier: GPL-2.0+

"""
Context
=======

VKMS uses u16 LUTs for color transfer functions. This script generates LUTs
while minimizing interpolation and quantization error without making them
unnecessarily large.

Three LUT generation methods are compared with this script:

    1. uniform: distribute points uniformly in the domain.
    2. inverse uniform: distribute points uniformly in the range.
    3. greedy subdivision: iteratively adds points where interpolation error is
       highest.

Since VKMS LUTs use u16 values, max_error is evaluated at all 65536 possible
input values, comparing to the original continuous curve. For each color curve,
the LUT size is chosen so the error is close to the u16 quantization step
(roughly 10^-5). Greedy subdivision performed best for all transfer functions of
interest, so this script generates the corresponding C arrays to be used by VKMS
(see vkms_luts.c).

Error evaluation
================

To evaluate the LUTs, we compare the interpolated result against the original
continuous curve at all 65536 possible u16 input values. Sampling between u16
values could report errors that VKMS cannot encounter, since its input is always
a u16 value, so there is no benefit in using more samples.

We initially experimented with float LUTs, where more samples were useful, and
the results were similar: greedy subdivision outperformed the other methods.

LUT size selection
==================

u16 quantization step is roughly 10^-5 in normalized space. So for each curve we
target LUT interpolation error close to or below this (making errors negligible
in the pipeline), and select the minimum LUT size that satisfies this target.

Inverse PQ requires a much higher LUT size than the other curves to satisfy this
error metric. This is expected, as it has a high slope near-zero.

Results
=======

As stated, greedy subdivision improves the results significantly. Besides
accounting for interpolation error, it also accounts for quantization error.
Uniform LUTs perform well for curves similar to power-law, while inverse uniform
LUTs perform well for curves similar to inverse power-law. Still, for u16 LUTs
greedy subdivision algorithm outperforms both.

Here are the LUT sizes and errors at which the error converged to the target
error:

Results using greedy subdivision u16 LUTs
----------------------------------------------
Function               LUT size   Max error
----------------------------------------------
pow 2.2                270        9.320331e-06
inverse pow 2.2        370        1.056258e-05
piece-wise sRGB        260        9.298192e-06
inv piece-wise sRGB    330        1.001394e-05
PQ                     380        9.159226e-06
inverse PQ             540        9.476497e-06
BT.2020 OETF           270        9.762646e-06
inv BT.2020 OETF       240        9.924004e-06
----------------------------------------------

Note: inverse pow 2.2 and inverse piece-wise sRGB LUTs stopped improving with
fewer taps than inverse PQ, but their max_error didn't drop below 10^-5, even
with very large LUTs. This can be attributed to quantization error.
"""

import sys
import os
import time
import bisect
import math
import numpy as np


def u16_to_float(u16_val):
    """Convert u16 value to normalized float [0, 1]"""
    return u16_val / 65535.0


def float_to_u16(float_val):
    """Convert normalized float [0, 1] to u16"""
    return int(np.round(np.clip(float_val * 65535.0, 0, 65535)))


class LUT:
    """
    Base class for all LUT.
    """
    def __init__(self, name, function_pair, lut_size):
        self.name = name
        self.lut_size = lut_size
        self.func = function_pair[0]
        self.inverse_func = function_pair[1]
        self.x = None
        self.y = None
        self.x_float = None  # cached float x array for interpolation
        self.y_float = None  # cached float y array for interpolation
        self.build_lut()
        self.validate()
        self.cache_float()

    def validate(self):
        """Sanity-check the generated LUT arrays"""
        errors = []

        if self.lut_size < 2:
            errors.append(f"LUT size ({self.lut_size}) < 2")
        if len(self.x) != self.lut_size:
            errors.append(f"x length ({len(self.x)}) != lut_size ({self.lut_size})")
        if len(self.y) != self.lut_size:
            errors.append(f"y length ({len(self.y)}) != lut_size ({self.lut_size})")

        # All curves start with (0, 0) and end with (1, 1)
        if self.x[0] != 0:
            errors.append(f"x[0] = {self.x[0]}, expected 0")
        if self.x[-1] != 65535:
            errors.append(f"x[-1] = {self.x[-1]}, expected 65535")
        if self.y[0] != 0:
            errors.append(f"y[0] = {self.y[0]}, expected 0")
        if self.y[-1] != 65535:
            errors.append(f"y[-1] = {self.y[-1]}, expected 65535")

        # X must be strictly increasing (no repeated points)
        for i in range(1, self.lut_size):
            if self.x[i] <= self.x[i - 1]:
                errors.append(f"x not strictly increasing at index {i}: "
                              f"x[{i-1}]={self.x[i-1]}, x[{i}]={self.x[i]}")
                break

        # Y must be non-decreasing (all supported TFs are increasing on [0,1],
        # so the quantized output should never decrease)
        for i in range(1, self.lut_size):
            if self.y[i] < self.y[i - 1]:
                errors.append(f"y decreases between index {i-1} and {i}: "
                              f"y[{i-1}]={self.y[i-1]}, y[{i}]={self.y[i]}")
                break

        if errors:
            print(f"\n[{self.name}] VALIDATION FAILED:")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)

    def cache_float(self):
        """Cache u16 x and y arrays as float for interpolation"""
        self.x_float = self.x / 65535.0
        self.y_float = self.y / 65535.0

    @staticmethod
    def lut_interp(x, x_array, y_array):
        """
        Lookup with linear interpolation using binary search.
        All inputs and output are floats in [0, 1].
        """
        if x <= x_array[0]:
            return y_array[0]
        if x >= x_array[-1]:
            return y_array[-1]

        # Use bisect for Python lists, np.searchsorted for numpy arrays. This
        # avoids type conversions that are extremely slow.
        if isinstance(x_array, list):
            i1 = bisect.bisect_left(x_array, x)
        else:
            i1 = np.searchsorted(x_array, x)

        i0 = i1 - 1

        x0, y0 = x_array[i0], y_array[i0]
        x1, y1 = x_array[i1], y_array[i1]

        return y0 + (x - x0) * (y1 - y0) / (x1 - x0)

    def build_lut(self):
        raise NotImplementedError

    def compute_error(self, num_samples=65536):
        """
        Compute average absolute error and max absolute error for this LUT.
        Samples all 65536 possible u16 input values, interpolates using cached
        float arrays, and compares to the continuous function.
        """
        average_abs_error = 0
        max_abs_error = 0
        max_abs_error_x = 0
        for i in range(num_samples):
            x = i / (num_samples - 1)
            lut_res = self.lut_interp(x, self.x_float, self.y_float)
            real_res = self.func(x)
            error = abs(real_res - lut_res)
            average_abs_error += error
            if error > max_abs_error:
                max_abs_error = error
                max_abs_error_x = x
        average_abs_error = average_abs_error / num_samples

        # Check if max_error occurs between two adjacent u16 x
        i1 = np.searchsorted(self.x_float, max_abs_error_x)
        i0 = i1 - 1
        if i0 >= 0 and i1 < self.lut_size:
            x0_u16 = self.x[i0]
            x1_u16 = self.x[i1]
            if x1_u16 - x0_u16 == 1:
                indent = " " * (len(self.name) + 3)
                print(f"[{self.name}] Warning: max_error at x={max_abs_error_x:.6e}\n"
                      f"{indent}is between adjacent u16 x points ({x0_u16}, {x1_u16}).\n"
                      f"{indent}Increasing LUT size probably won't help.")

        return average_abs_error, max_abs_error


class LUT_uniform(LUT):
    """
    Regular uniform LUT, equidistant points in the domain
    """
    def __init__(self, function_pair, lut_size):
        super().__init__("Uniform", function_pair, lut_size)

    def build_lut(self):
        x_list = []
        y_list = []
        for i in range(self.lut_size):
            # Generate x uniformly in u16 space [0, 65535]
            x_u16 = min(65535, round(i * 65535 / (self.lut_size - 1)))
            x_float = u16_to_float(x_u16)
            y_float = self.func(x_float)
            x_list.append(x_u16)
            y_list.append(float_to_u16(y_float))

        self.x = np.array(x_list, dtype=np.uint16)
        self.y = np.array(y_list, dtype=np.uint16)


class LUT_inverse_uniform(LUT):
    """
    Inverse uniform LUT: uniformly spaces y values and computes x = f_inv(y).
    Similar to inverting x and y arrays from regular LUT. This naturally places
    more points in regions where the function has high slope (e.g. near zero for
    inverse power-law curves).
    """
    def __init__(self, function_pair, lut_size):
        super().__init__("Inverse uniform", function_pair, lut_size)

    def build_lut(self):
        # Uniformly space points in the range, compute x = inverse_func(y)
        x_list = []
        y_list = []
        for i in range(self.lut_size):
            y_u16 = min(65535, round(i * 65535 / (self.lut_size - 1)))
            x_u16 = float_to_u16(self.inverse_func(u16_to_float(y_u16)))

            # Ignore duplicates.
            if x_list and x_u16 == x_list[-1]:
                continue

            x_list.append(x_u16)
            # As x_u16 may contain quantization error (it is the result of
            # computing inverse_func(y) but rounded to closest quantization
            # step), let's recompute y_u16 based on x_u16 using func(). This
            # creates a more precise LUT.
            y_list.append(float_to_u16(self.func(u16_to_float(x_u16))))

        self.x = np.array(x_list, dtype=np.uint16)
        self.y = np.array(y_list, dtype=np.uint16)

        # Update size, as we may have ignored duplicates
        self.lut_size = len(x_list)


class LUT_greedy_subdivision(LUT):
    """
    This greedily looks for domain points in which the interpolation error is
    maximal, and keeps adding points in such regions to reduce the LUT error.

    The code here only samples the midpoint of each segment to compute error,
    not the true maximum error point in the segment. This is an approximation,
    and one would have to try several points in the segments to have even more
    accurate results. But the midpoint heuristic is fast and accurate enough.

    Note: the optimal solution (optimal in terms of minimizing interpolation
    error) for the approximation problem would be using the method of globally
    optimal knot placement, but that's much more complex. This one is good
    enough.
    """
    def __init__(self, function_pair, lut_size):
        super().__init__("Greedy subdivision", function_pair, lut_size)

    def build_lut(self):
        # Use Python lists during construction, as it's much faster to
        # dynamically change their size.
        x_list = [0, 65535]
        y_list = [float_to_u16(self.func(0.0)), float_to_u16(self.func(1.0))]

        # Maintain float lists for interpolation during construction
        x_list_float = [0.0, 1.0]
        y_list_float = [u16_to_float(y_list[0]), u16_to_float(y_list[1])]

        # Add points based on max error
        while len(x_list) < self.lut_size:
            max_error = 0.0
            width_cur = 0.0
            index = 0
            best_x_mid_u16 = None

            # Find segment with max error
            for i in range(len(x_list) - 1):
                x0_u16 = x_list[i]
                x1_u16 = x_list[i + 1]
                segment_width_u16 = x1_u16 - x0_u16

                # Skip segments in which we can't add more points in between
                if segment_width_u16 < 2:
                    continue

                # Calculate midpoint in u16 space
                x_mid_u16 = (x0_u16 + x1_u16) // 2
                x_mid_float = u16_to_float(x_mid_u16)

                # Compute error at midpoint
                y_sample = self.func(x_mid_float)
                y_interp = self.lut_interp(x_mid_float, x_list_float, y_list_float)
                segment_max_error = abs(y_sample - y_interp)

                # Prefer biggest segment to tie-break error == max_error. This
                # avoids issues with e.g. linear segments. In these segments,
                # the error is always zero, so we need to add points evenly
                # spaced.
                if (segment_max_error > max_error or
                    (math.isclose(segment_max_error, max_error, abs_tol=1e-6) and
                     segment_width_u16 > width_cur)):
                    max_error = segment_max_error
                    index = i
                    width_cur = segment_width_u16
                    best_x_mid_u16 = x_mid_u16

            # If no valid segment found, stop. Also update size as we may have
            # converged without the LUT size given by end user.
            if best_x_mid_u16 is None:
                self.lut_size = len(x_list)
                break

            x_mid_float = u16_to_float(best_x_mid_u16)
            y_mid_float = self.func(x_mid_float)
            y_mid_u16 = float_to_u16(y_mid_float)

            x_list.insert(index + 1, best_x_mid_u16)
            y_list.insert(index + 1, y_mid_u16)
            x_list_float.insert(index + 1, x_mid_float)
            y_list_float.insert(index + 1, u16_to_float(y_mid_u16))

        self.x = np.array(x_list, dtype=np.uint16)
        self.y = np.array(y_list, dtype=np.uint16)


class Functions:
    """
    Functions and their inverse
    """
    @staticmethod
    def pow22(x):
        return pow(x, 2.2)

    @staticmethod
    def inv_pow22(x):
        return pow(x, 1.0 / 2.2)

    @staticmethod
    def srgb(x):
        if x <= 0.04045:
            return x / 12.92
        return pow(((x + 0.055) / 1.055), 2.4)

    @staticmethod
    def inv_srgb(x):
        if x <= 0.0031308:
            return 12.92 * x
        return 1.055 * pow(x, (1.0 / 2.4)) - 0.055

    @staticmethod
    def pq(x):
        m1_inv = 1.0 / 0.1593017578125
        m2_inv = 1.0 / 78.84375
        c1 = 0.8359375
        c2 = 18.8515625
        c3 = 18.6875
        aux = pow(x, m2_inv)
        return pow(max(aux - c1, 0.0) / (c2 - c3 * aux), m1_inv)

    @staticmethod
    def inv_pq(x):
        m1 = 0.1593017578125
        m2 = 78.84375
        c1 = 0.8359375
        c2 = 18.8515625
        c3 = 18.6875
        aux = pow(x, m1)
        return pow((c1 + c2 * aux) / (1.0 + c3 * aux), m2)

    @staticmethod
    def bt2020_oetf(x):
        a = 1.0993
        if x < 0.018:
            return 4.5 * x
        return a * (pow(x, 0.45)) - (a - 1.0)

    @staticmethod
    def inv_bt2020_oetf(x):
        a = 1.0993
        if x < 0.081:
            return x / 4.5
        k = (x + a - 1.0) / a
        return pow(k, 1.0 / 0.45)


def emit_c_arrays(lut, func_str):
    """
    Write X and Y arrays in C format compatible with vkms_luts.c to a file.
    """
    name = func_str

    output_file = f"{func_str}{lut.lut_size}.txt"
    if os.path.isfile(output_file):
        print(f"  File {output_file} already exists, not overriding it")
        return

    lines = []

    # X array: format eight values per line.
    lines.append(f"static u16 {name}_x[] = {{")
    for i in range(0, lut.lut_size, 8):
        chunk = lut.x[i:i+8]
        vals = ", ".join(f"0x{int(v):04x}" for v in chunk)
        comma = "," if i + 8 < lut.lut_size else ""
        lines.append(f"\t{vals}{comma}")
    lines.append("};")
    lines.append("")

    # Y array: one struct drm_color_lut entry per line: { R = val, G = val, B = val, reserved = 0 }
    lines.append(f"static struct drm_color_lut {name}_y[] = {{")
    for i, y_val in enumerate(lut.y):
        v = int(y_val)
        comma = "," if i < lut.lut_size - 1 else ""
        lines.append(f"\t{{ 0x{v:04x}, 0x{v:04x}, 0x{v:04x}, 0 }}{comma}")
    lines.append("};")

    output = "\n".join(lines) + "\n"

    with open(output_file, 'w') as f:
        f.write(output)
    print(f"  C arrays written to {output_file}")


def print_help_and_quit(function_table):
    """
    Print usage message and quit
    """
    print("Usage: python script.py <function> <LUT_size> [--plot]")
    print("  -h, --help    Show this help message and exit")
    print("  --plot        Display the LUT plots")
    print("LUT size in range [2, 4096]")
    print("LUTs based on greedy subdivision algorithm are printed to file <function><LUT_size>.txt")
    print("Possible function names are:")
    for func in function_table.keys():
        print(f"  {func}")
        print(f"  inv_{func}")
    sys.exit(1)


def parse_cli_params(args, function_table):
    """
    Parse cli params from users
    """
    if len(args) not in (3, 4):
        print_help_and_quit(function_table)

    plot = False
    if len(args) == 4:
        if args[3] != "--plot":
            print(f"Error: unknown option '{args[3]}'\n")
            print_help_and_quit(function_table)
        plot = True

    func_str = args[1]
    use_inverse = func_str.startswith("inv_")
    base_func_str = func_str[4:] if use_inverse else func_str

    func_pair = function_table.get(base_func_str)
    if func_pair is None:
        print(f"Error: unknown function '{func_str}'\n")
        print_help_and_quit(function_table)

    if use_inverse:
        func_pair = (func_pair[1], func_pair[0])

    lut_size_str = args[2]
    try:
        lut_size = int(lut_size_str)
        if lut_size < 2 or lut_size > 4096:
            print(f"Error: LUT size '{lut_size}' not in valid range\n")
            print_help_and_quit(function_table)
    except ValueError:
        print(f"Error: '{lut_size_str}' is not a valid LUT size\n")
        print_help_and_quit(function_table)

    return func_str, func_pair, lut_size, plot


def main(args):
    function_table = {
        "srgb": (Functions.srgb, Functions.inv_srgb),
        "pow22": (Functions.pow22, Functions.inv_pow22),
        "pq": (Functions.pq, Functions.inv_pq),
        "bt2020_oetf": (Functions.bt2020_oetf, Functions.inv_bt2020_oetf),
    }

    func_str, func_pair, lut_size, plot = parse_cli_params(args, function_table)

    start_time = time.perf_counter()

    luts = [LUT_uniform(func_pair, lut_size),
            LUT_inverse_uniform(func_pair, lut_size),
            LUT_greedy_subdivision(func_pair, lut_size)]

    luts_error = [lut.compute_error() for lut in luts]

    print(f"\nFunction: {func_str}, LUT size (specified by user): {lut_size}\n")
    print(f"{'LUT Type':<41} {'Average Error':>15} {'Max Error':>11}")
    print("-" * 72)

    for i, lut in enumerate(luts):
        avg_error, max_error = luts_error[i]
        label = f"{lut.name:<20} (actual size: {lut.lut_size})"
        print(f"{label:<40} {avg_error:>15.6e} {max_error:>15.6e}")

    end_time = time.perf_counter()
    print(f"\nTime to compute LUTs and errors: {end_time - start_time:.4f} seconds")

    # Save the greedy subdivision LUT as C arrays for VKMS
    greedy_lut = luts[2]
    emit_c_arrays(greedy_lut, func_str)

    if not plot:
        return

    import matplotlib.pyplot as plt

    # Plot the LUTs... kind of useless when we have a big LUT, but still good to
    # visualize with fewer taps.
    fig, axes = plt.subplots(1, len(luts), figsize=(15, 6))
    for i, lut in enumerate(luts):
        ax = axes[i]
        ax.set_title(f"{lut.name} - {func_str}, LUT size: {lut.lut_size}")
        ax.set_xlabel('X')
        ax.set_ylabel('Y')
        ax.grid(True, linestyle='--')
        ax.plot(lut.x, lut.y, 'o', color="blue")
        ax.set_aspect('equal')
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main(sys.argv)
