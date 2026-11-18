/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_HMM_H
#define __BACKPORT_LINUX_HMM_H

#include_next <linux/hmm.h>

#ifdef BPM_HMM_PFN_TO_PHYS_NOT_PRESENT
static inline phys_addr_t hmm_pfn_to_phys(unsigned long hmm_pfn)
{
	return __pfn_to_phys(hmm_pfn & ~HMM_PFN_FLAGS);
}
#endif

#ifdef BPM_HMM_RANGE_FAULT_UNLOCKED_TIMEOUT_NOT_PRESENT
#include <linux/jiffies.h>
#include <linux/mmap_lock.h>
#include <linux/oom.h>
#include <linux/sched/signal.h>

static inline int
hmm_range_fault_unlocked_timeout(struct hmm_range *range, unsigned long timeout)
{
	struct mm_struct *mm = range->notifier->mm;
	unsigned long deadline = jiffies + timeout;
	int ret;

	do {
		if (fatal_signal_pending(current))
			return -EINTR;

		range->notifier_seq = mmu_interval_read_begin(range->notifier);
		ret = mmap_read_lock_killable(mm);
		if (ret)
			return ret;

		if (check_stable_address_space(mm))
			ret = -EFAULT;
		else if (timeout && time_after(jiffies, deadline))
			ret = -EBUSY;
		else
			/* Legacy HMM keeps mmap_lock held throughout the walk. */
			ret = hmm_range_fault(range);

		mmap_read_unlock(mm);
		if (timeout && time_after(jiffies, deadline))
			break;
	} while (ret == -EBUSY);

	return ret;
}
#endif

#endif /* __BACKPORT_LINUX_HMM_H */
