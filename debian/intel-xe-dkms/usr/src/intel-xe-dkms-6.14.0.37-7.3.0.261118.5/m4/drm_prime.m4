dnl #
dnl # v6.6-71e801b9b44f
dnl # drm: Clear fd/handle callbacks in struct drm_driver.
dnl #
AC_DEFUN([AC_DRM_DRIVER_PRIME_CALLBACKS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_drv.h>
			#include <drm/drm_prime.h>
		],[
			struct drm_driver drv = { 0 };
			drv.prime_handle_to_fd = drm_gem_prime_handle_to_fd;
			drv.prime_fd_to_handle = drm_gem_prime_fd_to_handle;
		],[
		],[
			AC_DEFINE(BPM_DRM_DRIVER_PRIME_CALLBACKS_NOT_PRESENT, 1,
				[drm_driver PRIME callback fields are not available])
		])
	])
])
