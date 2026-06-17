dnl #
dnl # v6.6-e6303f323b1ad
dnl # drm: manager to keep track of GPUs VA mappings
dnl #
AC_DEFUN([AC_DRM_GEM_OBJECT_GPUVA_MEMBER_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_gem.h>
                ],[
                        struct drm_gem_object obj;
                        (void)obj.gpuva.list;
                ],[
                        dnl # gpuva present in kernel struct – no action needed
                ],[
                        AC_DEFINE(BPM_DRM_GEM_OBJECT_GPUVA_MEMBER_NOT_PRESENT, 1,
                                [kernel drm_gem_object lacks gpuva field (pre-v6.1 kernels)])
                ])
        ])
])
