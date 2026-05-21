/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_SLAB_H
#define __BACKPORT_LINUX_SLAB_H

#include_next <linux/mm.h>
#include_next <linux/slab.h>
#include <linux/module.h>

#ifdef BPM_KVREALLOC_OLDSIZE_PARAM_PRESENT
static inline void *__bp_kvrealloc(const void *p, size_t newsize, gfp_t flags)
{
	return kvrealloc(p, 0, newsize, flags);
}
#define kvrealloc(p, s, f) __bp_kvrealloc(p, s, f)
#endif

#endif /* __BACKPORT_LINUX_SLAB_H */
