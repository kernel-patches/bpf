/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * PTP 1588 clock support - user space interface
 *
 * Copyright (C) 2010 OMICRON electronics GmbH
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _PTP_CLOCK_H_
#define _PTP_CLOCK_H_

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * Bits of the ptp_extts_request.flags field:
 */
#define PTP_ENABLE_FEATURE (1<<0)
#define PTP_RISING_EDGE    (1<<1)
#define PTP_FALLING_EDGE   (1<<2)
#define PTP_STRICT_FLAGS   (1<<3)
#define PTP_EXT_OFFSET     (1<<4)
#define PTP_EXTTS_EDGES    (PTP_RISING_EDGE | PTP_FALLING_EDGE)

/*
 * flag fields valid for the new PTP_EXTTS_REQUEST2 ioctl.
 *
 * Note: PTP_STRICT_FLAGS is always enabled by the kernel for
 * PTP_EXTTS_REQUEST2 regardless of whether it is set by userspace.
 */
#define PTP_EXTTS_VALID_FLAGS	(PTP_ENABLE_FEATURE |	\
				 PTP_RISING_EDGE |	\
				 PTP_FALLING_EDGE |	\
				 PTP_STRICT_FLAGS |	\
				 PTP_EXT_OFFSET)

/*
 * flag fields valid for the original PTP_EXTTS_REQUEST ioctl.
 * DO NOT ADD NEW FLAGS HERE.
 */
#define PTP_EXTTS_V1_VALID_FLAGS	(PTP_ENABLE_FEATURE |	\
					 PTP_RISING_EDGE |	\
					 PTP_FALLING_EDGE)

/*
 * flag fields valid for the ptp_extts_event report.
 */
#define PTP_EXTTS_EVENT_VALID	(PTP_ENABLE_FEATURE)

/*
 * Bits of the ptp_perout_request.flags field:
 */
#define PTP_PEROUT_ONE_SHOT		(1<<0)
#define PTP_PEROUT_DUTY_CYCLE		(1<<1)
#define PTP_PEROUT_PHASE		(1<<2)

/*
 * flag fields valid for the new PTP_PEROUT_REQUEST2 ioctl.
 */
#define PTP_PEROUT_VALID_FLAGS		(PTP_PEROUT_ONE_SHOT | \
					 PTP_PEROUT_DUTY_CYCLE | \
					 PTP_PEROUT_PHASE)

/*
 * No flags are valid for the original PTP_PEROUT_REQUEST ioctl
 */
#define PTP_PEROUT_V1_VALID_FLAGS	(0)

/*
 * Clock status values for struct ptp_clock_attrs.status
 */
enum ptp_clock_status {
	/* Clock synchronization status cannot be reliably determined */
	PTP_CLOCK_STATUS_UNKNOWN      = 0,

	/* Clock is acquiring synchronization */
	PTP_CLOCK_STATUS_INITIALIZING = 1,

	/* Clock is synchronized and maintained accurately by the device */
	PTP_CLOCK_STATUS_SYNCED       = 2,

	/*
	 * Clock is drifting but remains within acceptable error bounds;
	 * error_bound is valid and can be trusted.
	 */
	PTP_CLOCK_STATUS_HOLDOVER     = 3,

	/*
	 * Clock is free-running: not currently disciplined toward a reference
	 * (unlike HOLDOVER), but coasting on a known oscillator. error_bound
	 * remains valid and can be trusted, and typically grows over time.
	 */
	PTP_CLOCK_STATUS_FREE_RUNNING = 4,

	/*
	 * Clock is considered broken (e.g. the oscillator is faulty or
	 * abnormally unstable): error_bound cannot be trusted. A clock that is
	 * merely unsynchronized or resynchronizing should report
	 * PTP_CLOCK_STATUS_UNKNOWN or PTP_CLOCK_STATUS_INITIALIZING instead.
	 */
	PTP_CLOCK_STATUS_UNRELIABLE   = 5
};

/*
 * Clock timescale values for struct ptp_clock_attrs.timescale.
 *
 * These definitions describe the mathematical properties and reference
 * epochs of the timescale provided by the PHC.
 *
 * Discipline: Describes the frequency/phase steering behavior.
 * Continuity: Describes whether the timeline is uninterrupted.
 */
enum ptp_clock_timescale {
	/* Unknown or unspecified timescale */
	PTP_TIMESCALE_UNKNOWN = 0,

	/********************* Absolute Atomic Timescales *********************
	 * These timescales are continuous, monotonic standards based on atomic
	 * physics. They do not experience phase jumps.
	 **********************************************************************/

	/**
	 * International Atomic Time (TAI)
	 * Epoch: 1958-01-01 00:00:00.
	 * Continuity: Strictly monotonic and continuous; no leap seconds.
	 * Discipline: Primary atomic reference; no phase jumps.
	 */
	PTP_TIMESCALE_TAI = 1,

	/**
	 * Terrestrial Time (TT)
	 * Epoch: 1958-01-01 00:00:00.
	 * Continuity: Strictly monotonic and continuous; no leap seconds.
	 * Discipline: Defined as TAI + 32.184s constant offset.
	 */
	PTP_TIMESCALE_TT = 2,

	/**
	 * Global Positioning System (GPS) Time
	 * Epoch: 1980-01-06 00:00:00.
	 * Continuity: Strictly monotonic and continuous; no leap seconds.
	 * Discipline: Defined by the GPS constellation; fixed offset from TAI.
	 */
	PTP_TIMESCALE_GPS = 3,

	/****************** UTC-Based Timescales (Civil Time) *****************
	 * These timescales are derived from TAI but adjusted to align with
	 * the Earth's rotation, primarily through leap seconds.
	 **********************************************************************/

	/**
	 * Coordinated Universal Time (UTC) - Wall-clock (CLOCK_REALTIME)
	 * Epoch: 1970-01-01 00:00:00 (Unix epoch).
	 * Continuity: Discontinuous; subject to 1-second leap second
	 *             phase jumps.
	 * Discipline: Frequency steered; incorporates leap second corrections.
	 *
	 * Note: Leap-smeared UTC MUST NOT be advertised as PTP_TIMESCALE_UTC.
	 * Smear algorithms are not standardized and the resulting timescale
	 * is ambiguous. Implementations using smeared UTC MUST advertise
	 * PTP_TIMESCALE_UNKNOWN or PTP_TIMESCALE_PROPRIETARY instead.
	 */
	PTP_TIMESCALE_UTC = 4,

	/**
	 * POSIX Time (Unix Time)
	 * Epoch: 1970-01-01 00:00:00.
	 * Continuity: Discontinuous; leap seconds handled by
	 *             repeating/skipping values.
	 * Discipline: Follows UTC frequency steering and phase jumps.
	 */
	PTP_TIMESCALE_POSIX = 5,

	/****************** System-Relative Monotonic Clocks ******************
	 * These timescales are relative to a system event (like boot)
	 * and are not synchronized to an external atomic standard.
	 **********************************************************************/

	/**
	 * Monotonic System Clock (CLOCK_MONOTONIC)
	 * Epoch: Arbitrary (System boot time).
	 * Continuity: Strictly monotonic; no leap seconds.
	 * Discipline: Frequency steered to match system reference;
	 *             does not advance during suspend.
	 */
	PTP_TIMESCALE_MONOTONIC = 6,

	/**
	 * Raw Monotonic System Clock (CLOCK_MONOTONIC_RAW)
	 * Epoch: Arbitrary (System boot time).
	 * Continuity: Strictly monotonic; no leap seconds.
	 * Discipline: Raw hardware oscillator; no frequency steering
	 *             or discipline.
	 */
	PTP_TIMESCALE_MONOTONIC_RAW = 7,

	/**
	 * Boot Time System Clock (CLOCK_BOOTTIME)
	 * Epoch: Arbitrary (System boot time).
	 * Continuity: Strictly monotonic and continuous; no leap seconds.
	 * Discipline: Frequency steered to match system reference;
	 *             advances during suspend.
	 */
	PTP_TIMESCALE_BOOTTIME = 8,

	/********************** Vendor-Specific Timescale *********************/

	/* A proprietary or vendor-specific timescale with custom rules. */
	PTP_TIMESCALE_PROPRIETARY = 9,
};

/*
 * struct ptp_clock_time - represents a time value
 *
 * The sign of the seconds field applies to the whole value. The
 * nanoseconds field is always unsigned. The reserved field is
 * included for sub-nanosecond resolution, should the demand for
 * this ever appear.
 *
 */
struct ptp_clock_time {
	__s64 sec;  /* seconds */
	__u32 nsec; /* nanoseconds */
	__u32 reserved;
};

/*
 * Hardware counter identifiers for struct ptp_sys_time.sys_counter_id
 */
enum ptp_counter_id {
	/* Counter value not available or type not specified */
	PTP_COUNTER_UNKNOWN = 0,

	/* x86 Time Stamp Counter (TSC) */
	PTP_COUNTER_X86_TSC = 1,

	/* ARM Generic Timer virtual counter */
	PTP_COUNTER_ARM_ARCH = 2,
};

/* Valid flags for struct ptp_clock_attrs.valid */
#define PTP_ATTRS_VALID_ERROR_BOUND	(1 << 0)
#define PTP_ATTRS_VALID_TIMESCALE	(1 << 1)
#define PTP_ATTRS_VALID_STATUS		(1 << 2)

/**
 * struct ptp_clock_attrs - quality attributes for a PHC timestamp
 *
 * @valid:       Bitmask of PTP_ATTRS_VALID_* indicating which fields
 *               are populated. Zero means no attributes available.
 * @error_bound: Maximum error (an upper bound, in nanoseconds) between the
 *               returned device_time and true time on the advertised
 *               @timescale; a worst-case bound, not a statistical estimate.
 *               Valid only when PTP_ATTRS_VALID_ERROR_BOUND is set, and must
 *               not be trusted when @status is PTP_CLOCK_STATUS_UNKNOWN or
 *               PTP_CLOCK_STATUS_UNRELIABLE.
 * @timescale:   Clock timescale (enum ptp_clock_timescale). Valid only
 *               when PTP_ATTRS_VALID_TIMESCALE is set.
 * @status:      Synchronization status (enum ptp_clock_status). Valid
 *               only when PTP_ATTRS_VALID_STATUS is set. Transitions between
 *               states are device-specific; there are no kernel-defined
 *               thresholds relating @status to @error_bound.
 * @rsv:         Reserved for future use, must be zero.
 */
struct ptp_clock_attrs {
	__u32 valid;
	__u32 error_bound;
	__u32 timescale;
	__u32 status;
	__u32 rsv[4];
};

/**
 * struct ptp_sys_time - system time snapshot with counter value
 *
 * @sys_time:       System time in nanoseconds (clock selected by request).
 * @sys_rawtime:    CLOCK_MONOTONIC_RAW time in nanoseconds.
 * @sys_counter:    Raw clocksource counter value (0 = unavailable).
 * @sys_counter_id: Identifies the counter (enum ptp_counter_id).
 * @rsv:            Reserved for future use, must be zero.
 */
struct ptp_sys_time {
	__s64 sys_time;
	__s64 sys_rawtime;
	__u64 sys_counter;
	__u32 sys_counter_id;
	__u32 rsv;
};

/**
 * struct ptp_dev_time - device timestamp with quality attributes
 *
 * @device_time: PHC timestamp value.
 * @attrs:       Quality attributes for this timestamp.
 */
struct ptp_dev_time {
	struct ptp_clock_time device_time;
	struct ptp_clock_attrs attrs;
};

/**
 * struct ptp_timestamp - a complete timestamp sample
 *
 * @systime:      System time snapshot; shares storage with @pre_systime,
 *                used by PTP_SYS_OFFSET_PRECISE_ATTRS.
 * @pre_systime:  System time read right before the device read, used by
 *                PTP_SYS_OFFSET_EXTENDED_ATTRS.
 * @devtime:      Device timestamp with its quality attributes.
 * @post_systime: System time read right after the device read, used by
 *                PTP_SYS_OFFSET_EXTENDED_ATTRS.
 *
 * For PTP_SYS_OFFSET_EXTENDED_ATTRS: pre_systime and post_systime bracket
 * the device read (ABA sandwich).
 * For PTP_SYS_OFFSET_PRECISE_ATTRS: only systime (union with pre_systime)
 * is meaningful; post_systime is zeroed.
 */
struct ptp_timestamp {
	union {
		struct ptp_sys_time systime;
		struct ptp_sys_time pre_systime;
	};
	struct ptp_dev_time devtime;
	struct ptp_sys_time post_systime;
};

/**
 * struct ptp_attrs_request - request parameters for attrs ioctls
 *
 * @valid:       Bitmask for future request extensions. Must be zero for now.
 * @clock_id:    Clock base for system timestamps (CLOCK_REALTIME, etc).
 * @num_samples: Number of timestamp samples requested.
 *               For PTP_SYS_OFFSET_PRECISE_ATTRS must be 1.
 * @rsv:         Reserved for future use, must be zero.
 */
struct ptp_attrs_request {
	__u32 valid;
	__kernel_clockid_t clock_id;
	__u32 num_samples;
	__u32 rsv[3];
};

/**
 * struct ptp_sys_offset_attrs - unified data structure for attrs ioctls
 *
 * @request:    Request parameters (see struct ptp_attrs_request).
 * @timestamps: Array of returned samples; holds request.num_samples entries.
 *
 * Used by both PTP_SYS_OFFSET_EXTENDED_ATTRS and
 * PTP_SYS_OFFSET_PRECISE_ATTRS. Userspace allocates space for
 * request.num_samples entries in the timestamps array.
 */
struct ptp_sys_offset_attrs {
	struct ptp_attrs_request request;
	struct ptp_timestamp timestamps[];
};

struct ptp_clock_caps {
	int max_adj;   /* Maximum frequency adjustment in parts per billon. */
	int n_alarm;   /* Number of programmable alarms. */
	int n_ext_ts;  /* Number of external time stamp channels. */
	int n_per_out; /* Number of programmable periodic signals. */
	int pps;       /* Whether the clock supports a PPS callback. */
	int n_pins;    /* Number of input/output pins. */
	/* Whether the clock supports precise system-device cross timestamps */
	int cross_timestamping;
	/* Whether the clock supports adjust phase */
	int adjust_phase;
	int max_phase_adj; /* Maximum phase adjustment in nanoseconds. */
	/* Whether the clock supports extended timestamps with attributes */
	int extended_attrs;
	/* Whether the clock supports precise cross-timestamps with attributes */
	int precise_attrs;
	int rsv[9];       /* Reserved for future use. */
};

struct ptp_extts_request {
	unsigned int index;  /* Which channel to configure. */
	unsigned int flags;  /* Bit field for PTP_xxx flags. */
	unsigned int rsv[2]; /* Reserved for future use. */
};

struct ptp_perout_request {
	union {
		/*
		 * Absolute start time.
		 * Valid only if (flags & PTP_PEROUT_PHASE) is unset.
		 */
		struct ptp_clock_time start;
		/*
		 * Phase offset. The signal should start toggling at an
		 * unspecified integer multiple of the period, plus this value.
		 * The start time should be "as soon as possible".
		 * Valid only if (flags & PTP_PEROUT_PHASE) is set.
		 */
		struct ptp_clock_time phase;
	};
	struct ptp_clock_time period; /* Desired period, zero means disable. */
	unsigned int index;           /* Which channel to configure. */
	unsigned int flags;
	union {
		/*
		 * The "on" time of the signal.
		 * Must be lower than the period.
		 * Valid only if (flags & PTP_PEROUT_DUTY_CYCLE) is set.
		 */
		struct ptp_clock_time on;
		/* Reserved for future use. */
		unsigned int rsv[4];
	};
};

#define PTP_MAX_SAMPLES 25 /* Maximum allowed offset measurement samples. */

struct ptp_sys_offset {
	unsigned int n_samples; /* Desired number of measurements. */
	unsigned int rsv[3];    /* Reserved for future use. */
	/*
	 * Array of interleaved system/phc time stamps. The kernel
	 * will provide 2*n_samples + 1 time stamps, with the last
	 * one as a system time stamp.
	 */
	struct ptp_clock_time ts[2 * PTP_MAX_SAMPLES + 1];
};

/*
 * ptp_sys_offset_extended - data structure for IOCTL operation
 *			     PTP_SYS_OFFSET_EXTENDED
 *
 * @n_samples:	Desired number of measurements.
 * @clockid:	clockid of a clock-base used for pre/post timestamps.
 * @rsv:	Reserved for future use.
 * @ts:		Array of samples in the form [pre-TS, PHC, post-TS]. The
 *		kernel provides @n_samples.
 *
 * Starting from kernel 6.12 and onwards, the first word of the reserved-field
 * is used for @clockid. That's backward compatible since previous kernel
 * expect all three reserved words (@rsv[3]) to be 0 while the clockid (first
 * word in the new structure) for CLOCK_REALTIME is '0'.
 */
struct ptp_sys_offset_extended {
	unsigned int n_samples;
	__kernel_clockid_t clockid;
	unsigned int rsv[2];
	struct ptp_clock_time ts[PTP_MAX_SAMPLES][3];
};

struct ptp_sys_offset_precise {
	struct ptp_clock_time device;
	struct ptp_clock_time sys_realtime;
	struct ptp_clock_time sys_monoraw;
	unsigned int rsv[4];    /* Reserved for future use. */
};

enum ptp_pin_function {
	PTP_PF_NONE,
	PTP_PF_EXTTS,
	PTP_PF_PEROUT,
	PTP_PF_PHYSYNC,
};

struct ptp_pin_desc {
	/*
	 * Hardware specific human readable pin name. This field is
	 * set by the kernel during the PTP_PIN_GETFUNC ioctl and is
	 * ignored for the PTP_PIN_SETFUNC ioctl.
	 */
	char name[64];
	/*
	 * Pin index in the range of zero to ptp_clock_caps.n_pins - 1.
	 */
	unsigned int index;
	/*
	 * Which of the PTP_PF_xxx functions to use on this pin.
	 */
	unsigned int func;
	/*
	 * The specific channel to use for this function.
	 * This corresponds to the 'index' field of the
	 * PTP_EXTTS_REQUEST and PTP_PEROUT_REQUEST ioctls.
	 */
	unsigned int chan;
	/*
	 * Reserved for future use.
	 */
	unsigned int rsv[5];
};

#define PTP_CLK_MAGIC '='

#define PTP_CLOCK_GETCAPS  _IOR(PTP_CLK_MAGIC, 1, struct ptp_clock_caps)
#define PTP_EXTTS_REQUEST  _IOW(PTP_CLK_MAGIC, 2, struct ptp_extts_request)
#define PTP_PEROUT_REQUEST _IOW(PTP_CLK_MAGIC, 3, struct ptp_perout_request)
#define PTP_ENABLE_PPS     _IOW(PTP_CLK_MAGIC, 4, int)
#define PTP_SYS_OFFSET     _IOW(PTP_CLK_MAGIC, 5, struct ptp_sys_offset)
#define PTP_PIN_GETFUNC    _IOWR(PTP_CLK_MAGIC, 6, struct ptp_pin_desc)
#define PTP_PIN_SETFUNC    _IOW(PTP_CLK_MAGIC, 7, struct ptp_pin_desc)
#define PTP_SYS_OFFSET_PRECISE \
	_IOWR(PTP_CLK_MAGIC, 8, struct ptp_sys_offset_precise)
#define PTP_SYS_OFFSET_EXTENDED \
	_IOWR(PTP_CLK_MAGIC, 9, struct ptp_sys_offset_extended)

#define PTP_CLOCK_GETCAPS2  _IOR(PTP_CLK_MAGIC, 10, struct ptp_clock_caps)
#define PTP_EXTTS_REQUEST2  _IOW(PTP_CLK_MAGIC, 11, struct ptp_extts_request)
#define PTP_PEROUT_REQUEST2 _IOW(PTP_CLK_MAGIC, 12, struct ptp_perout_request)
#define PTP_ENABLE_PPS2     _IOW(PTP_CLK_MAGIC, 13, int)
#define PTP_SYS_OFFSET2     _IOW(PTP_CLK_MAGIC, 14, struct ptp_sys_offset)
#define PTP_PIN_GETFUNC2    _IOWR(PTP_CLK_MAGIC, 15, struct ptp_pin_desc)
#define PTP_PIN_SETFUNC2    _IOW(PTP_CLK_MAGIC, 16, struct ptp_pin_desc)
#define PTP_SYS_OFFSET_PRECISE2 \
	_IOWR(PTP_CLK_MAGIC, 17, struct ptp_sys_offset_precise)
#define PTP_SYS_OFFSET_EXTENDED2 \
	_IOWR(PTP_CLK_MAGIC, 18, struct ptp_sys_offset_extended)
#define PTP_MASK_CLEAR_ALL  _IO(PTP_CLK_MAGIC, 19)
#define PTP_MASK_EN_SINGLE  _IOW(PTP_CLK_MAGIC, 20, unsigned int)
#define PTP_SYS_OFFSET_PRECISE_CYCLES \
	_IOWR(PTP_CLK_MAGIC, 21, struct ptp_sys_offset_precise)
#define PTP_SYS_OFFSET_EXTENDED_CYCLES \
	_IOWR(PTP_CLK_MAGIC, 22, struct ptp_sys_offset_extended)
#define PTP_SYS_OFFSET_PRECISE_ATTRS \
	_IOWR(PTP_CLK_MAGIC, 23, struct ptp_sys_offset_attrs)
#define PTP_SYS_OFFSET_EXTENDED_ATTRS \
	_IOWR(PTP_CLK_MAGIC, 24, struct ptp_sys_offset_attrs)

struct ptp_extts_event {
	struct ptp_clock_time t; /* Time event occurred. */
	unsigned int index;      /* Which channel produced the event. */
	unsigned int flags;      /* Event type. */
	unsigned int rsv[2];     /* Reserved for future use. */
};

#endif
