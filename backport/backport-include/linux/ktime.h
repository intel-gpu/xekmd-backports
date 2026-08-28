/*
 *  include/linux/ktime.h
 *
 *  ktime_t - nanosecond-resolution time format.
 *
 *   Copyright(C) 2005, Linutronix GmbH, Thomas Gleixner <tglx@kernel.org>
 *   Copyright(C) 2005, Red Hat, Inc., Ingo Molnar
 *
 *  data type definitions, declarations, prototypes and macros.
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 *
 *  Credits:
 *
 *  	Roman Zippel provided the ideas and primary code snippets of
 *  	the ktime_t union and further simplifications of the original
 *  	code.
 *
 *  For licencing details see kernel-base/COPYING
 */
#ifndef _BACKPORT_KTIME_H
#define _BACKPORT_KTIME_H

#include_next <linux/ktime.h>

#ifdef BPM_US_TO_KTIME_NOT_PRESENT
static inline ktime_t us_to_ktime(u64 us)
{
	return us * NSEC_PER_USEC;
}
#endif

#endif
