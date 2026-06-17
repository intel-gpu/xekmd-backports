/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_UACCESS_H__
#define __BACKPORT_UACCESS_H__

#include_next <linux/uaccess.h>

#ifndef untagged_addr_remote
#define untagged_addr_remote(mm, addr)	({		\
	mmap_assert_locked(mm);				\
	untagged_addr(addr);				\
})
#endif

#endif /* __BACKPORT_UACCESS_H__ */
