dnl #
dnl #  v7.3 - 1219731c49e5
dnl #  mm: introduce and use vma_end_pgoff()
dnl #
dnl #  v7.3 - 51943a18ad4b
dnl #  mm: provide vma_[flags_]is_cow_mapping() and remove is_cow_mapping()
dnl #
dnl #  v7.3 - a2fdfd0080a3
dnl #  mm: introduce vma_get_page_prot() and use it
dnl #

AC_DEFUN([AC_VMA_COMPAT_HELPERS], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			(void)vma_end_pgoff(NULL);
		], [
		], [
			AC_DEFINE(BPM_VMA_END_PGOFF_NOT_PRESENT, 1,
				  [vma_end_pgoff() is not available])
		])
	])
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			(void)vma_is_cow_mapping(NULL);
		], [
		], [
			AC_DEFINE(BPM_VMA_IS_COW_MAPPING_NOT_PRESENT, 1,
				  [vma_is_cow_mapping() is not available])
		])
	])
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		], [
			(void)vma_get_page_prot(NULL);
		], [
		], [
			AC_DEFINE(BPM_VMA_GET_PAGE_PROT_NOT_PRESENT, 1,
				  [vma_get_page_prot() is not available])
		])
	])
])
