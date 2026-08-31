dnl #
dnl # v6.1-45dca1575964
dnl # netlink: add helpers for extack attr presence checking
dnl #
AC_DEFUN([AC_GENL_REQ_ATTR_CHECK_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <net/genetlink.h>
                        #ifndef GENL_REQ_ATTR_CHECK
                        #error GENL_REQ_ATTR_CHECK is not present
                        #endif
                ],[
                ],[
                ],[
                        AC_DEFINE(BPM_GENL_REQ_ATTR_CHECK_NOT_PRESENT, 1,
                                [GENL_REQ_ATTR_CHECK() macro is not available])
                ])
        ])
])
