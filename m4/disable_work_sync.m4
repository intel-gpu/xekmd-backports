dnl #
dnl # v6.10-86898fa6b8cd
dnl # workqueue: Implement disable/enable for (delayed) work items
dnl #
AC_DEFUN([AC_DISBALE_WORK_SYNC_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/workqueue.h>
                ],[
			disable_work_sync(NULL);
                ],[
		],[
			AC_DEFINE(BPM_DISBALE_WORK_SYNC_NOT_PRESENT, 1,
                                [disable_work_sync() function is not avilable])
                ])
        ])
])
