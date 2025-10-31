// SPDX-License-Identifier: GPL-2.0
/*
 *  hrtimers - High-resolution kernel timers
 *
 *   Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 *   Copyright(C) 2005, Red Hat, Inc., Ingo Molnar
 *
 *  data type definitions, declarations, prototypes
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 */
#ifndef __BACKPORT_HRTIMER_H
#define __BACKPORT_HRTIMER_H

#include_next<linux/hrtimer.h>

#ifdef BPM_HRTIMER_SETUP_NOT_PRESENT
extern void hrtimer_setup(struct hrtimer *timer,
			  enum hrtimer_restart (*function)(struct hrtimer *),
			  clockid_t clock_id, enum hrtimer_mode mode);
#endif

#endif /* __BACKPORT_HRTIMER_H */
