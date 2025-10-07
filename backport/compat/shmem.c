/*
 * Resizable virtual memory filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *		 2000 Transmeta Corp.
 *		 2000-2001 Christoph Rohland
 *		 2000-2001 SAP AG
 *		 2002 Red Hat Inc.
 * Copyright (C) 2002-2011 Hugh Dickins.
 * Copyright (C) 2011 Google Inc.
 * Copyright (C) 2002-2005 VERITAS Software Corporation.
 * Copyright (C) 2004 Andi Kleen, SuSE Labs
 *
 * Extended attribute support for tmpfs:
 * Copyright (c) 2004, Luke Kenneth Casson Leighton <lkcl@lkcl.net>
 * Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * tiny-shmem:
 * Copyright (c) 2004, 2008 Matt Mackall <mpm@selenic.com>
 *
 * This file is released under the GPL.
 */

/**
 * shmem_writeout - Write the folio to swap
 * @folio: The folio to write
 * @plug: swap plug
 * @folio_list: list to put back folios on split
 *
 * Move the folio from the page cache to the swap cache.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/ramfs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/fileattr.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/export.h>
#include <linux/shmem_fs.h>
#include <linux/swap.h>
#include <linux/uio.h>
#include <linux/hugetlb.h>
#include <linux/fs_parser.h>
#include <linux/swapfile.h>
#include <linux/iversion.h>

int shmem_writeout(struct folio *folio, struct swap_iocb **plug,
		struct list_head *folio_list)
{
#if 0
	struct address_space *mapping = folio->mapping;
	struct inode *inode = mapping->host;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	pgoff_t index;
	int nr_pages;
	bool split = false;

	if ((info->flags & VM_LOCKED) || sbinfo->noswap)
		goto redirty;

	if (!total_swap_pages)
		goto redirty;

	/*
	 * If CONFIG_THP_SWAP is not enabled, the large folio should be
	 * split when swapping.
	 *
	 * And shrinkage of pages beyond i_size does not split swap, so
	 * swapout of a large folio crossing i_size needs to split too
	 * (unless fallocate has been used to preallocate beyond EOF).
	 */
	if (folio_test_large(folio)) {
		index = shmem_fallocend(inode,
			DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE));
		if ((index > folio->index && index < folio_next_index(folio)) ||
		    !IS_ENABLED(CONFIG_THP_SWAP))
			split = true;
	}

	if (split) {
try_split:
		/* Ensure the subpages are still dirty */
		folio_test_set_dirty(folio);
		if (split_folio_to_list(folio, folio_list))
			goto redirty;
		folio_clear_dirty(folio);
	}

	index = folio->index;
	nr_pages = folio_nr_pages(folio);

	/*
	 * This is somewhat ridiculous, but without plumbing a SWAP_MAP_FALLOC
	 * value into swapfile.c, the only way we can correctly account for a
	 * fallocated folio arriving here is now to initialize it and write it.
	 *
	 * That's okay for a folio already fallocated earlier, but if we have
	 * not yet completed the fallocation, then (a) we want to keep track
	 * of this folio in case we have to undo it, and (b) it may not be a
	 * good idea to continue anyway, once we're pushing into swap.  So
	 * reactivate the folio, and let shmem_fallocate() quit when too many.
	 */
	if (!folio_test_uptodate(folio)) {
		if (inode->i_private) {
			struct shmem_falloc *shmem_falloc;
			spin_lock(&inode->i_lock);
			shmem_falloc = inode->i_private;
			if (shmem_falloc &&
			    !shmem_falloc->waitq &&
			    index >= shmem_falloc->start &&
			    index < shmem_falloc->next)
				shmem_falloc->nr_unswapped += nr_pages;
			else
				shmem_falloc = NULL;
			spin_unlock(&inode->i_lock);
			if (shmem_falloc)
				goto redirty;
		}
		folio_zero_range(folio, 0, folio_size(folio));
		flush_dcache_folio(folio);
		folio_mark_uptodate(folio);
	}

	if (!folio_alloc_swap(folio, __GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN)) {
		bool first_swapped = shmem_recalc_inode(inode, 0, nr_pages);
		int error;

		/*
		 * Add inode to shmem_unuse()'s list of swapped-out inodes,
		 * if it's not already there.  Do it now before the folio is
		 * removed from page cache, when its pagelock no longer
		 * protects the inode from eviction.  And do it now, after
		 * we've incremented swapped, because shmem_unuse() will
		 * prune a !swapped inode from the swaplist.
		 */
		if (first_swapped) {
			spin_lock(&shmem_swaplist_lock);
			if (list_empty(&info->swaplist))
				list_add(&info->swaplist, &shmem_swaplist);
			spin_unlock(&shmem_swaplist_lock);
		}

		swap_shmem_alloc(folio->swap, nr_pages);
		shmem_delete_from_page_cache(folio, swp_to_radix_entry(folio->swap));

		BUG_ON(folio_mapped(folio));
		error = swap_writeout(folio, plug);
		if (error != AOP_WRITEPAGE_ACTIVATE) {
			/* folio has been unlocked */
			return error;
		}

		/*
		 * The intention here is to avoid holding on to the swap when
		 * zswap was unable to compress and unable to writeback; but
		 * it will be appropriate if other reactivate cases are added.
		 */
		error = shmem_add_to_page_cache(folio, mapping, index,
				swp_to_radix_entry(folio->swap),
				__GFP_HIGH | __GFP_NOMEMALLOC | __GFP_NOWARN);
		/* Swap entry might be erased by racing shmem_free_swap() */
		if (!error) {
			shmem_recalc_inode(inode, 0, -nr_pages);
			swap_free_nr(folio->swap, nr_pages);
		}

		/*
		 * The delete_from_swap_cache() below could be left for
		 * shrink_folio_list()'s folio_free_swap() to dispose of;
		 * but I'm a little nervous about letting this folio out of
		 * shmem_writeout() in a hybrid half-tmpfs-half-swap state
		 * e.g. folio_mapping(folio) might give an unexpected answer.
		 */
		delete_from_swap_cache(folio);
		goto redirty;
	}
	if (nr_pages > 1)
		goto try_split;
redirty:
	folio_mark_dirty(folio);
	return AOP_WRITEPAGE_ACTIVATE;	/* Return with folio locked */
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(shmem_writeout);
