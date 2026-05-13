dnl #
dnl # v6.3-f01b2b3ed873
dnl # shmem: add shmem_read_folio() and shmem_read_folio_gfp()
dnl #
AC_DEFUN([AC_SHMEM_READ_FOLIO_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/shmem_fs.h>
		], [
			(void)shmem_read_folio(NULL, 0);
		], [
		], [
			AC_DEFINE(BPM_SHMEM_READ_FOLIO_NOT_PRESENT, 1,
				  [shmem_read_folio() is not available in the kernel])
		])
	])
])

AC_DEFUN([AC_SHMEM_READ_FOLIO_GFP_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/shmem_fs.h>
		], [
			(void)shmem_read_folio_gfp(NULL, 0, 0);
		], [
		], [
			AC_DEFINE(BPM_SHMEM_READ_FOLIO_GFP_NOT_PRESENT, 1,
				  [shmem_read_folio_gfp() is not available in the kernel])
		])
	])
])
