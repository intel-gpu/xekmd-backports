/* SPDX-License-Identifier: GPL-2.0 */
/*
 * compat: hmm_pfn_to_phys() (upstream v6.15, commit e2b0a6ef7a45 "mm/hmm:
 * provide generic DMA managing logic"), which is just the existing
 * hmm_pfn_to_page() arithmetic without the struct page round trip.
 */
#ifndef __XE_PONTOON_COMPAT_LINUX_HMM_H__
#define __XE_PONTOON_COMPAT_LINUX_HMM_H__

#include_next <linux/hmm.h>

#ifndef hmm_pfn_to_phys
static inline phys_addr_t hmm_pfn_to_phys(unsigned long hmm_pfn)
{
	return __pfn_to_phys(hmm_pfn & ~HMM_PFN_FLAGS);
}
#define hmm_pfn_to_phys hmm_pfn_to_phys
#endif

#endif /* __XE_PONTOON_COMPAT_LINUX_HMM_H__ */
