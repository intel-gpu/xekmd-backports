dnl #
dnl # v6.15-e53c1e263e5c
dnl # drm/gpuvm: Add DRM_GPUVA_OP_DRIVER
dnl #
AC_DEFUN([AC_DRM_GPUVA_OP_DRIVER_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_gpuva_mgr.h>
		],[
			DRM_GPUVA_OP_DRIVER;
		],[
		],[
                        AC_DEFINE(BPM_DRM_GPUVA_OP_DRIVER_NOT_PRESENT, 1,
                                [DRM_GPUVA_OP_DRIVER enum member is not avilable])
                ])
        ])
])
