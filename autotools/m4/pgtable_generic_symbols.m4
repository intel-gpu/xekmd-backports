dnl #
dnl # Test whether __pte_offset_map(), __pte_offset_map_lock(), and
dnl # pmd_clear_bad() are exported for modules.
dnl #
AC_DEFUN([AC_PGTABLE_GENERIC_SYMBOL_EXPORTS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE_SYMBOL([
			#include <linux/mm.h>
			#include <linux/pgtable.h>
		],[
			pmd_t *pmd = NULL;
			struct mm_struct *mm = NULL;
			spinlock_t *ptl = NULL;
			pte_t *pte;

			pmd_clear_bad(pmd);
			pte = __pte_offset_map(pmd, 0, NULL);
			pte = __pte_offset_map_lock(mm, pmd, 0, &ptl);
			(void)pte;
		],[__pte_offset_map __pte_offset_map_lock pmd_clear_bad],
		[mm/pgtable-generic.c],[
		],[
			AC_DEFINE(BPM_PGTABLE_GENERIC_SYMBOL_EXPORTS_NOT_PRESENT, 1,
				[__pte_offset_map(), __pte_offset_map_lock(), and pmd_clear_bad() are not exported])
		])
	])
])
