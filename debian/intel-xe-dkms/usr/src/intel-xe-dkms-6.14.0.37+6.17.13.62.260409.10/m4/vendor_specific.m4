dnl #
dnl # v6.18-9c857a9d84e0
dnl # drm: Add a vendor-specific recovery method to drm device wedged uevent
dnl #
AC_DEFUN([AC_DRM_WEDGE_RECOVERY_VENDOR_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_device.h>
                ],[
                        int recovery = DRM_WEDGE_RECOVERY_VENDOR;
                        (void)recovery;
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_WEDGE_RECOVERY_VENDOR_NOT_PRESENT, 1,
                                [DRM_WEDGE_RECOVERY_VENDOR flag not present])
                ])
        ])
])
