// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/export.h>
#include <drm/drm_buddy.h>

#if !defined(HAVE_LINUX_GPU_BUDDY_H_AVAILABLE) && !defined(CPTCFG_BUILD_XE_DRM_BUDDY)
struct drm_buddy_block *
backport_gpu_buddy_allocated_addr_to_block(struct drm_buddy *mm, u64 addr)
{
	struct drm_buddy_block *block;
	LIST_HEAD(dfs);
	u64 end;
	int i;

	end = addr + mm->chunk_size - 1;
	for (i = 0; i < mm->n_roots; ++i)
		list_add_tail(&mm->roots[i]->tmp_link, &dfs);

	do {
		u64 block_start;
		u64 block_end;

		block = list_first_entry_or_null(&dfs, struct drm_buddy_block, tmp_link);
		if (!block)
			break;

		list_del(&block->tmp_link);

		block_start = drm_buddy_block_offset(block);
		block_end = block_start + drm_buddy_block_size(mm, block) - 1;


		if (addr > block_end || block_start > end)
			continue;

		if (drm_buddy_block_is_allocated(block))
			return block;
		else if (drm_buddy_block_is_free(block))
			return NULL;

		list_add(&block->right->tmp_link, &dfs);
		list_add(&block->left->tmp_link, &dfs);
	} while (1);

	return ERR_PTR(-ENXIO);
}
EXPORT_SYMBOL(backport_gpu_buddy_allocated_addr_to_block);
#endif
