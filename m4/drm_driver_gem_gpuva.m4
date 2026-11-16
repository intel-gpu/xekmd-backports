dnl #
dnl #  v7.3 - 21fcb222f0d1
dnl #  drm: Remove DRIVER_GEM_GPUVA feature flag
dnl #

AC_DEFUN([AC_DRM_DRIVER_GEM_GPUVA_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_drv.h>
		], [
			enum drm_driver_feature feature = DRIVER_GEM_GPUVA;

			(void)feature;
		], [
			AC_DEFINE(BPM_DRM_DRIVER_GEM_GPUVA_PRESENT, 1,
				  [Target DRM core provides DRIVER_GEM_GPUVA])
		], [
		])
	])
])
