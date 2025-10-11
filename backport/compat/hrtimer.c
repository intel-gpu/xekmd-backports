// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 *  Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 *  Copyright(C) 2006-2007  Timesys Corp., Thomas Gleixner
 *
 *  High-resolution kernel timers
 *
 *  In contrast to the low-resolution timeout API, aka timer wheel,
 *  hrtimers provide finer resolution and accuracy depending on system
 *  configuration and capabilities.
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 *
 *  Credits:
 *	Based on the original timer wheel code
 *
 *	Help, testing, suggestions, bugfixes, improvements were
 *	provided by:
 *
 *	George Anzinger, Andrew Morton, Steven Rostedt, Roman Zippel
 *	et. al.
 */

#include <linux/hrtimer.h>

#ifdef BPM_HRTIMER_SETUP_NOT_PRESENT

/**
 * hrtimer_setup - initialize a timer to the given clock
 * @timer:      the timer to be initialized
 * @function:   the callback function
 * @clock_id:   the clock to be used
 * @mode:       The modes which are relevant for initialization:
 *              HRTIMER_MODE_ABS, HRTIMER_MODE_REL, HRTIMER_MODE_ABS_SOFT,
 *              HRTIMER_MODE_REL_SOFT
 *
 *              The PINNED variants of the above can be handed in,
 *              but the PINNED bit is ignored as pinning happens
 *              when the hrtimer is started
 */
void hrtimer_setup(struct hrtimer *timer, enum hrtimer_restart (*function)(struct hrtimer *),
                   clockid_t clock_id, enum hrtimer_mode mode)
{
        hrtimer_init(timer, clock_id, mode);
}
EXPORT_SYMBOL_GPL(hrtimer_setup);

#endif
