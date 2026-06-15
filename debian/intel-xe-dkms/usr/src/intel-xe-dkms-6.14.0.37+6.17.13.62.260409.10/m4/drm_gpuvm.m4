dnl #
dnl # v6.8-b06d47be7c83
dnl # drm/xe: Port Xe to GPUVA
dnl #
AC_DEFUN([AC_DRM_GPUVM_RENAMING_SYMBOLS], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_gpuvm.h>
                        #include <drm/drm_gem.h>
                ],[
                        struct drm_gpuvm_bo *bo = NULL;
                        drm_gpuvm_bo_put(bo);
                ],[
		],[
                        AC_KERNEL_TRY_COMPILE([
                                #include <drm/drm_gpuvm.h>
                        ],[
                                struct drm_gpuva_op_map test_map;
                                struct drm_gpuva test_va;
                        ],[
			],[
                                AC_DEFINE(BPM_DRM_GPUVM_RENAMING_SYMBOLS, 1,
                                        [rename DRM GPUVM symbols to avoid conflicts with backport kernel implementation])
                        ],[
                        ])
                ])
        ])
])
