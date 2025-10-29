dnl #
dnl # v6.13-cdd30ebb1b9f 
dnl # module: Convert symbol namespace to string literal
dnl #
AC_DEFUN([AC_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/module.h>
                ],[
                        MODULE_IMPORT_NS(TEST_NAMESPACE);
                ],[
                        AC_DEFINE(BPM_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT, 1,
                                [module_import_ns quoted namespace strings are not supported])
                ])
        ])
])
