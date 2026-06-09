dnl #
dnl # v5.17-365481e42a8a
dnl # driver core: auxiliary bus: Add driver data helpers
dnl #
AC_DEFUN([AC_AUXILIARY_BUS_HELPERS_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/auxiliary_bus.h>
                ],[
			struct auxiliary_device *auxdev = NULL;
			(void)auxiliary_get_drvdata(auxdev);
			auxiliary_set_drvdata(auxdev, NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_AUXILIARY_BUS_HELPERS_NOT_PRESENT, 1,
                                [auxiliary_get_drvdata and auxiliary_set_drvdata is not available])
                ])
        ])
])
