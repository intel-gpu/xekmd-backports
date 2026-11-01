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

#endif /* __BACKPORT_LINUX_HMM_H */
