dnl #
dnl # v6.18-e7fa80e2932c6
dnl # drm_gem: add mutex to drm_gem_object.gpuva
dnl #
AC_DEFUN([AC_DRM_GEM_GPUVA_MUTEX_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_gem.h>
                ],[
                        struct drm_gem_object obj;
                        struct mutex *mu = &obj.gpuva.lock;
                        (void)mu;
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_GEM_GPUVA_MUTEX_NOT_PRESENT, 1,
                                [drm_gem_object.gpuva.lock (struct mutex) not present; kernel uses lock_dep_map pointer or no lock field])
                ])
        ])
])
