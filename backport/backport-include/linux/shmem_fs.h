/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_SHMEM_FS_H
#define __BACKPORT_LINUX_SHMEM_FS_H

#include_next <linux/shmem_fs.h>
#include <linux/mm.h>

#ifdef BPM_SHMEM_READ_FOLIO_NOT_PRESENT
#define shmem_read_folio(mapping, idx) \
	((struct folio *)shmem_read_mapping_page_gfp((mapping), (idx), \
						     mapping_gfp_mask(mapping)))
#endif

#ifdef BPM_SHMEM_READ_FOLIO_GFP_NOT_PRESENT
#define shmem_read_folio_gfp(mapping, idx, gfp) \
	((struct folio *)shmem_read_mapping_page_gfp((mapping), (idx), (gfp)))
#endif

#endif /* __BACKPORT_LINUX_SHMEM_FS_H */
