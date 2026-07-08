/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_SHRINKER_H__
#define __BACKPORT_LINUX_SHRINKER_H__

#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/atomic.h>

#include_next <linux/shrinker.h>

#ifdef BPM_REGISTER_SHRINKER_ARG2_NOT_PRESENT
/*
 * Legacy kernels expose register_shrinker(struct shrinker *) only.
 * Drop optional format/name arguments used by newer callsites.
 */
#define register_shrinker(shrinker, ...) register_shrinker(shrinker)
#endif

#endif /* __BACKPORT_LINUX_SHRINKER_H__ */
