dnl #
dnl # v6.10-7bd230a26648
dnl # kvrealloc_noprof: 3-arg version (oldsize parameter removed)
dnl #
AC_DEFUN([AC_KVREALLOC_NOPROF_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/slab.h>
		],[
			void *p = NULL;
			kvrealloc_noprof(p, 16, GFP_KERNEL);
		],[
			AC_DEFINE(BPM_KVREALLOC_NOPROF_PRESENT, 1,
				[kvrealloc_noprof() is available])
		],[
		])
	])
])
