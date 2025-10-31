dnl #
dnl # Test for access_remote_vm() function availability
dnl #

AC_DEFUN([AC_ACCESS_REMOTE_VM_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/mm.h>
		],[
			struct mm_struct *mm = NULL;
			unsigned long addr = 0;
			void *buf = NULL;
			int len = 0;
			unsigned int gup_flags = 0;
			void *func_ptr;

			func_ptr = access_remote_vm;
			(void)func_ptr;
		],[
		],[
			AC_DEFINE(BPM_ACCESS_REMOTE_VM_NOT_PRESENT, 1,
				[access_remote_vm() function is not exported])
		])
	])
])
