/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_KERNEL_H
#define _BACKPORT_LINUX_KERNEL_H

#include_next <linux/kernel.h>

#ifndef container_of_const
#define container_of_const(ptr, type, member) \
        container_of((ptr), type, member)
#endif

#endif /* _BACKPORT_LINUX_KERNEL_H */
