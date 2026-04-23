/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_UACCESS_H__
#define __BACKPORT_UACCESS_H__

#include_next <linux/uaccess.h>

#ifdef BPM_UNTAGGED_ADDR_REMOTE_NOT_PRESENT
#ifndef untagged_addr_remote
#define untagged_addr_remote(mm, addr)	({		\
	mmap_assert_locked(mm);				\
	untagged_addr(addr);				\
})
#endif
#endif

#endif /* __BACKPORT_UACCESS_H__ */
