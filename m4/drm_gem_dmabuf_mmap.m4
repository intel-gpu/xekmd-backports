dnl #
dnl # 0adec22702d4 
dnl # drm: Remove struct drm_driver.gem_prime_mmap
dnl # 
AC_DEFUN([AC_DRM_DRIVER_GEM_PRIME_MMAP_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_drv.h>
		], [
			struct drm_driver drv = { 0 };
			drv.gem_prime_mmap = NULL;
		], [
			AC_DEFINE(BPM_DRM_DRIVER_GEM_PRIME_MMAP_PRESENT, 1,
				[struct drm_driver has gem_prime_mmap callback])
		], [
		])
	])
])
