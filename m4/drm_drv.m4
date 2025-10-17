dnl #
dnl # v6.14-7b0af165e2d4
dnl # drm/drv: Add drmm managed registration helper for dmem cgroups.
dnl #
AC_DEFUN([AC_DRMM_CGROUP_REGISTER_REGION_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/types.h>
			#include <drm/drm_device.h>
			#include <drm/drm_drv.h>
		],[
			struct drm_device *dev = NULL;
			struct drm_cgroup_state *cg;
			cg = drmm_cgroup_register_region(dev, "test", 1024);
			(void)cg;
		],[
		],[
			AC_DEFINE(BPM_DRMM_CGROUP_REGISTER_REGION_NOT_PRESENT, 1,
				[drmm_cgroup_register_region is declared in drm/drm_drv.h])
		])
	])
])
