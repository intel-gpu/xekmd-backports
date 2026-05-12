dnl #
dnl # v6.3-c1e3f1c611e6 mm: introduce vm_flags_set/vm_flags_clear
dnl #
AC_DEFUN([AC_VM_FLAGS_SET_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		],[
			struct vm_area_struct *vma = NULL;
			vm_flags_set(vma, 0);
		],[
		],[
			AC_DEFINE(BPM_VM_FLAGS_SET_NOT_PRESENT, 1,
				  [vm_flags_set() is not available in the kernel])
		])
	])
])
