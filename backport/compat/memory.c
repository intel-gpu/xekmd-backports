// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

/*
 * 05.04.94  -  Multi-page memory management added for v1.1.
 *              Idea by Alex Bligh (alex@cconcepts.co.uk)
 *
 * 16.07.99  -  Support of BIGMEM added by Gerhard Wichert, Siemens AG
 *		(Gerhard.Wichert@pdb.siemens.de)
 *
 * Aug/Sep 2004 Changed to four level page tables (Andi Kleen)
 */

#include <linux/mm.h>
#include <asm/pgtable.h>

#ifdef BPM_ACCESS_REMOTE_VM_NOT_PRESENT
int access_remote_vm(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, unsigned int gup_flags)
{
	int ret;
	struct task_struct *tsk = NULL;

	if (mm && mm->owner)
	{
		tsk = mm->owner;

		get_task_struct(tsk);  // Take reference

		ret = access_process_vm(tsk, addr, buf, len, gup_flags);

		put_task_struct(tsk);  // Release reference
	}
	else
	{
		pr_err("mm->owner has no task_struct (kernel thread)\n");
		ret = 0;
	}

	return ret;
}

EXPORT_SYMBOL(access_remote_vm);
#endif

#ifdef BPM_FOLLOW_PFNMAP_NOT_PRESENT
static inline void pfnmap_args_setup(struct follow_pfnmap_args *args,
				     spinlock_t *lock, pte_t *ptep,
				     pgprot_t pgprot, unsigned long pfn_base,
				     unsigned long addr_mask, bool writable,
				     bool special)
{
	args->lock = lock;
	args->ptep = ptep;
	args->pfn = pfn_base + ((args->address & ~addr_mask) >> PAGE_SHIFT);
	args->pgprot = pgprot;
	args->writable = writable;
	args->special = special;
}

static inline void pfnmap_lockdep_assert(struct vm_area_struct *vma)
{
#ifdef CONFIG_LOCKDEP
	struct file *file = vma->vm_file;
	struct address_space *mapping = file ? file->f_mapping : NULL;

	if (mapping)
		lockdep_assert(lockdep_is_held(&vma->vm_file->f_mapping->i_mmap_rwsem) ||
			       lockdep_is_held(&vma->vm_mm->mmap_lock));
	else
		lockdep_assert(lockdep_is_held(&vma->vm_mm->mmap_lock));
#endif
}

/**
 * follow_pfnmap_start() - Look up a pfn mapping at a user virtual address
 * @args: Pointer to struct @follow_pfnmap_args
 *
 * The caller needs to setup args->vma and args->address to point to the
 * virtual address as the target of such lookup.  On a successful return,
 * the results will be put into other output fields.
 *
 * After the caller finished using the fields, the caller must invoke
 * another follow_pfnmap_end() to proper releases the locks and resources
 * of such look up request.
 *
 * During the start() and end() calls, the results in @args will be valid
 * as proper locks will be held.  After the end() is called, all the fields
 * in @follow_pfnmap_args will be invalid to be further accessed.  Further
 * use of such information after end() may require proper synchronizations
 * by the caller with page table updates, otherwise it can create a
 * security bug.
 *
 * If the PTE maps a refcounted page, callers are responsible to protect
 * against invalidation with MMU notifiers; otherwise access to the PFN at
 * a later point in time can trigger use-after-free.
 *
 * Only IO mappings and raw PFN mappings are allowed.  The mmap semaphore
 * should be taken for read, and the mmap semaphore cannot be released
 * before the end() is invoked.
 *
 * This function must not be used to modify PTE content.
 *
 * Return: zero on success, negative otherwise.
 */
int follow_pfnmap_start(struct follow_pfnmap_args *args)
{
	struct vm_area_struct *vma = args->vma;
	unsigned long address = args->address;
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *lock;
	pgd_t *pgdp;
	p4d_t *p4dp, p4d;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;

	pfnmap_lockdep_assert(vma);

	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		goto out;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))
		goto out;
retry:
	pgdp = pgd_offset(mm, address);
	if (pgd_none(*pgdp) || unlikely(pgd_bad(*pgdp)))
		goto out;

	p4dp = p4d_offset(pgdp, address);
	p4d = READ_ONCE(*p4dp);
	if (p4d_none(p4d) || unlikely(p4d_bad(p4d)))
		goto out;

	pudp = pud_offset(p4dp, address);
	pud = READ_ONCE(*pudp);
	if (pud_none(pud))
		goto out;
	if (pud_leaf(pud)) {
		lock = pud_lock(mm, pudp);
		if (!unlikely(pud_leaf(pud))) {
			spin_unlock(lock);
			goto retry;
		}
		pfnmap_args_setup(args, lock, NULL, pud_pgprot(pud),
				  pud_pfn(pud), PUD_MASK, pud_write(pud),
				  pud_special(pud));
		return 0;
	}

	pmdp = pmd_offset(pudp, address);
	pmd = pmdp_get_lockless(pmdp);
	if (pmd_leaf(pmd)) {
		lock = pmd_lock(mm, pmdp);
		if (!unlikely(pmd_leaf(pmd))) {
			spin_unlock(lock);
			goto retry;
		}
		pfnmap_args_setup(args, lock, NULL, pmd_pgprot(pmd),
				  pmd_pfn(pmd), PMD_MASK, pmd_write(pmd),
				  pmd_special(pmd));
		return 0;
	}

	ptep = pte_offset_map_lock(mm, pmdp, address, &lock);
	if (!ptep)
		goto out;
	pte = ptep_get(ptep);
	if (!pte_present(pte))
		goto unlock;
	pfnmap_args_setup(args, lock, ptep, pte_pgprot(pte),
			  pte_pfn(pte), PAGE_MASK, pte_write(pte),
			  pte_special(pte));
	return 0;
unlock:
	pte_unmap_unlock(ptep, lock);
out:
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(follow_pfnmap_start);

/**
 * follow_pfnmap_end(): End a follow_pfnmap_start() process
 * @args: Pointer to struct @follow_pfnmap_args
 *
 * Must be used in pair of follow_pfnmap_start().  See the start() function
 * above for more information.
 */
void follow_pfnmap_end(struct follow_pfnmap_args *args)
{
	if (args->lock)
		spin_unlock(args->lock);
	if (args->ptep)
		pte_unmap(args->ptep);
}
EXPORT_SYMBOL_GPL(follow_pfnmap_end);
#endif
