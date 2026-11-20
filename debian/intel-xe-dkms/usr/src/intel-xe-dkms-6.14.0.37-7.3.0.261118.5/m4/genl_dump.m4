dnl #
dnl # v6.6-9272af109fe6
dnl # genetlink: add struct genl_info to struct genl_dumpit_info
dnl #
AC_DEFUN([AC_GENL_INFO_DUMP_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <net/genetlink.h>
                ], [
                        genl_info_dump(NULL);
                ], [
                ], [
                        AC_DEFINE(BPM_GENL_INFO_DUMP_NOT_PRESENT, 1,
                                [genl_info_dump() API is not available])
                ])
        ])
])
