/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_ASM_X86_PGTABLE_H
#define __BACKPORT_ASM_X86_PGTABLE_H

#include_next <asm/pgtable.h>

#ifdef BPM_FOLLOW_PFNMAP_NOT_PRESENT
#ifdef CONFIG_ARCH_SUPPORTS_PUD_PFNMAP
static inline bool pud_special(pud_t pud)
{
	return pud_flags(pud) & _PAGE_SPECIAL;
}
#else
static inline bool pud_special(pud_t pud)
{
	return false;
}
#endif	/* CONFIG_ARCH_SUPPORTS_PUD_PFNMAP */

#ifdef CONFIG_ARCH_SUPPORTS_PMD_PFNMAP
static inline bool pmd_special(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_SPECIAL;
}
#else
static inline bool pmd_special(pmd_t pmd)
{
	return false;
}
#endif	/* CONFIG_ARCH_SUPPORTS_PMD_PFNMAP */
#endif

#endif /* __BACKPORT_ASM_X86_PGTABLE_H */
