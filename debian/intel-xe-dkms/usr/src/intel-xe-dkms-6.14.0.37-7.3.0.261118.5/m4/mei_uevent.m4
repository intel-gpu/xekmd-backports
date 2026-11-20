dnl #
dnl # v6.10-2a81ada32f0e
dnl # driver core: make struct bus_type.uevent() take a const *
dnl #
AC_DEFUN([AC_MEI_CL_DEVICE_UEVENT_CONST_ARG_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/device.h>
                        #include <linux/device/bus.h>
                ],[
                        int mei_cl_device_uevent(const struct device *dev,
                                                 struct kobj_uevent_env *env);
                        struct bus_type test_bus = {
                                .uevent = mei_cl_device_uevent,
                        };
                        (void)test_bus;
                ],[
                ],[
                        AC_DEFINE([BPM_MEI_CL_DEVICE_UEVENT_CONST_ARG_NOT_PRESENT], 1,
                                [const argument not supported in struct bus_type uevent callback])
                ])
        ])
])
