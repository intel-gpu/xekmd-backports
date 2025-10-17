dnl #
dnl # v6.11-3b9c181bcde85
dnl # devcoredump: Add dev_coredumpm_timeout()
dnl #
AC_DEFUN([AC_COREDUMPM_TIMEOUT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/devcoredump.h>
                ],[
                        dev_coredumpm_timeout(NULL, NULL, NULL, 0, 0, NULL, NULL,0);
                ],[
		],[
                        AC_DEFINE(BPM_COREDUMPM_TIMEOUT_NOT_PRESENT, 1,
                                [dev_coredumpm_timeout() is not available])
                ])
        ])
])

dnl #
dnl # v6.10-a28380f119a9
dnl # devcoredump: Add dev_coredump_put()
dnl #
AC_DEFUN([AC_DEVCOREDUMP_PUT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/devcoredump.h>
                ],[
                        dev_coredump_put(NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_DEVCOREDUMP_PUT_NOT_PRESENT, 1,
                                [dev_coredump_put() is not available])
                ])
        ])
])
