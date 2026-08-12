dnl #
dnl # v6.4-43a7206b0963
dnl # driver core: class: make class_register() take a const *
dnl #
AC_DEFUN([AC_MEI_CLASS_BUS_REGISTER_CONST_ARGS_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/device/class.h>
                ],[
                        const struct class cls = {
                                .name = "mei_test_class",
                        };

                        return class_register(&cls);
                ],[
                ],[
                        AC_DEFINE([BPM_MEI_CLASS_BUS_REGISTER_CONST_ARGS_NOT_PRESENT], 1,
                                [class_register() does not take const struct class *])
                ])
        ])
])
