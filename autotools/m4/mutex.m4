dnl #
dnl # v5.15
dnl # Kernel may inline mutex_lock_interruptible and not export it for modules
dnl #
AC_DEFUN([AC_MUTEX_LOCK_INTERRUPTIBLE_EXPORTED], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/mutex.h>
                ],[
                        struct mutex lock = {};
                        (void)mutex_lock_interruptible(&lock);
                ],[
                ],[
                        AC_DEFINE(BPM_MUTEX_LOCK_INTERRUPTIBLE_NOT_EXPORTED, 1,
                                [mutex_lock_interruptible not exported for modules])
                ])
        ])
])
