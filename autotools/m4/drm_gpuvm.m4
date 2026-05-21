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

dnl #
dnl # v7.0-9bf4ca1e699c
dnl # drm/gpuvm: drm_gpuvm_bo_obtain() requires lock and staged mode
dnl #
AC_DEFUN([AC_DRM_GPUVM_BO_OBTAIN_LOCKED_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_gpuvm.h>
		],[
			struct drm_gpuvm_bo *vm_bo;
			vm_bo = drm_gpuvm_bo_obtain_locked(NULL, NULL);
		],[
		],[
			AC_DEFINE(BPM_DRM_GPUVM_BO_OBTAIN_LOCKED_NOT_PRESENT, 1,
				[drm_gpuvm_bo_obtain_locked() is not present])
		])
	])
])

dnl #
dnl # v7.0-baf1638c0956
dnl # drm/gpuvm: Introduce drm_gpuvm_madvise_ops_create
dnl #
AC_DEFUN([AC_DRM_GPUVM_MADVISE_OPS_CREATE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_gpuvm.h>
		],[
			struct drm_gpuva_ops *ops;
			ops = drm_gpuvm_madvise_ops_create(NULL, NULL);
		],[
		],[
			AC_DEFINE(BPM_DRM_GPUVM_MADVISE_OPS_CREATE_NOT_PRESENT, 1,
				[drm_gpuvm_madvise_ops_create() is not present])
		])
	])
])
