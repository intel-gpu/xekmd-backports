dnl #
dnl # v6.4-1fb1ea0d9cb8
dnl # mei: Move uuid.h to the MEI namespace
dnl #
AC_DEFUN([AC_LINUX_MEI_UUID_H_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/mei_uuid.h>
                ], [
                        uuid_le uuid = NULL_UUID_LE;
                        (void)uuid;
                ], [
                ], [
                        AC_DEFINE([BPM_LINUX_MEI_UUID_H_NOT_PRESENT], 1,
                                [linux/mei_uuid.h is not available])
                ])
        ])
])
