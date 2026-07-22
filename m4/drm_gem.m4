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

dnl #
dnl # v6.18-3c8d31b8937a
dnl # gpuvm: remove gem.gpuva.lock_dep_map
dnl #
AC_DEFUN([AC_DRM_GEM_GPUVA_LOCK_DEP_MAP_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_gem.h>
                ],[
                        struct drm_gem_object obj;
#ifdef CONFIG_LOCKDEP
                        /* Compile-time member existence check; fails if lock_dep_map is absent. */
                        typedef char __gpuva_lock_dep_map_member_exists[
                                sizeof(&obj.gpuva.lock_dep_map) ? 1 : -1
                        ];
                        struct lockdep_map **map = &obj.gpuva.lock_dep_map;
                        (void)sizeof(__gpuva_lock_dep_map_member_exists);
                        (void)map;
#endif
                ],[
                ],[
                        AC_DEFINE(BPM_DRM_GEM_GPUVA_LOCK_DEP_MAP_NOT_PRESENT, 1,
                                [drm_gem_object.gpuva.lock_dep_map not present when CONFIG_LOCKDEP is enabled])
                ])
        ])
])
