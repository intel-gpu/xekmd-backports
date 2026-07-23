/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_HUGE_MM_H
#define __BACKPORT_LINUX_HUGE_MM_H

#include_next <linux/huge_mm.h>

#ifdef BPM_VMF_INSERT_PFN_ARG_PFN_T_NOT_PRESENT
#include <linux/pfn_t.h>

static inline vm_fault_t backport_vmf_insert_pfn_pmd(struct vm_fault *vmf,
                                              unsigned long pfn,
                                              bool write)
{
        return vmf_insert_pfn_pmd(vmf, pfn_to_pfn_t(pfn), write);
}

static inline vm_fault_t backport_vmf_insert_pfn_pud(struct vm_fault *vmf,
                                              unsigned long pfn,
                                              bool write)
{
        return vmf_insert_pfn_pud(vmf, pfn_to_pfn_t(pfn), write);
}

#undef vmf_insert_pfn_pmd
#define vmf_insert_pfn_pmd(vmf, pfn, write) \
        backport_vmf_insert_pfn_pmd((vmf), (pfn), (write))

#undef vmf_insert_pfn_pud
#define vmf_insert_pfn_pud(vmf, pfn, write) \
        backport_vmf_insert_pfn_pud((vmf), (pfn), (write))
#endif

#endif /* __BACKPORT_LINUX_HUGE_MM_H */
