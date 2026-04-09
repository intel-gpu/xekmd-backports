dnl #
dnl # v6.15-4fab2d7628dd
dnl # objtool: Fix init_module() handling
dnl #
AC_DEFUN([AC_OBJTOOL_COPY_ATTRIBUTE_NEEDED], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/compiler_attributes.h>
                ],[
                        #ifndef __copy
                        #error __copy is not defined
                        #endif
                ],[
                        AC_DEFINE(BPM_OBJTOOL_COPY_ATTRIBUTE_NEEDED, 1,
                                [enable objtool-safe module init/exit aliases])
                ])
        ])
])
