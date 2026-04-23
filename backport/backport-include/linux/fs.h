/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_FS_H
#define _BACKPORT_FS_H

#include_next <linux/fs.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
#include <linux/slab.h>
#endif

#endif
