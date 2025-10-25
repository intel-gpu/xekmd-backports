/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_SHMEM_FS_H
#define __BACKPORT_SHMEM_FS_H

#include_next <linux/shmem_fs.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,7,0)
int shmem_writeout(struct folio *folio, struct swap_iocb **plug,
		struct list_head *folio_list);
#endif

#endif /* __BACKPORT_SHMEM_FS_H */
