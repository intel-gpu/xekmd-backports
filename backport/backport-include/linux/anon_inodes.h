/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/linux/anon_inodes.h
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _BACKPORT_ANON_INODES_H
#define _BACKPORT_ANON_INODES_H

#include_next <linux/anon_inodes.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
struct file *anon_inode_getfile_fmode(const char *name,
				const struct file_operations *fops,
				void *priv, int flags, fmode_t f_mode);
#endif

#endif
