dnl #
dnl #  v7.3 - a8efc69a65fb
dnl #  shmem: provide a shmem_write_folio wrapper
dnl #

AC_DEFUN([AC_SHMEM_WRITE_FOLIO_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/shmem_fs.h>
		], [
			(void)shmem_write_folio(NULL);
		], [
		], [
			AC_DEFINE(BPM_SHMEM_WRITE_FOLIO_NOT_PRESENT, 1,
				  [shmem_write_folio() is not available])
		])
	])
])
