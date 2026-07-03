/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_SLAB_H
#define __BACKPORT_LINUX_SLAB_H

#include_next <linux/slab.h>
#include <linux/module.h>

#ifdef BPM_KVREALLOC_OLDSIZE_PARAM_PRESENT
#ifndef BPM_KVREALLOC_NOPROF_PRESENT

#define __bp_kvrealloc_3(_p, _newsize, _flags) \
	kvrealloc(_p, 0, _newsize, _flags)
#define __bp_kvrealloc_4(_p, _oldsize, _newsize, _flags) \
	kvrealloc(_p, _oldsize, _newsize, _flags)
#define __bp_kvrealloc_pick(_1, _2, _3, _4, _pick, ...) _pick

#ifndef kvrealloc
#define kvrealloc(...) \
	__bp_kvrealloc_pick(__VA_ARGS__, __bp_kvrealloc_4, __bp_kvrealloc_3) \
	(__VA_ARGS__)
#endif

#endif
#endif

#endif /* __BACKPORT_LINUX_SLAB_H */
