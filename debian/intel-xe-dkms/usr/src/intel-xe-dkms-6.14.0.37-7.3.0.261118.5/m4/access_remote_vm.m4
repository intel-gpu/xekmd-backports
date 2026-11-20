dnl #
dnl #  v7.0 - 5ddd36b9c5
dnl #  mm: implement access_remote_vm
dnl #

AC_DEFUN([AC_ACCESS_REMOTE_VM_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/mm.h>
		],[
			(void)access_remote_vm;
		],[
			AC_DEFINE(BPM_ACCESS_REMOTE_VM_NOT_PRESENT, 1,
				[access_remote_vm() function is not present or not exported])
		])
	])
])
