dnl #
dnl # v6.6-5aa51d9f889c
dnl # genetlink: add genlmsg_iput() API
dnl #
AC_DEFUN([AC_GENLMSG_IPUT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <net/genetlink.h>
                ], [
                        genlmsg_iput(NULL, NULL);
                ], [
                ], [
                        AC_DEFINE(BPM_GENLMSG_IPUT_NOT_PRESENT, 1,
                                [genlmsg_iput() API is not available])
                ])
        ])
])
