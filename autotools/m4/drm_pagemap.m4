dnl #
dnl # v7.0 - a599b98607de
dnl # drm/pagemap, drm/xe: Add refcounting to struct drm_pagemap
dnl #
AC_DEFUN([AC_DRM_PAGEMAP_PUT_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_pagemap.h>
		],[
			struct drm_pagemap *dpagemap = NULL;
			drm_pagemap_put(dpagemap);
		],[
			AC_DEFINE(BPM_DRM_PAGEMAP_PUT_PRESENT, 1,
				[drm_pagemap_put() is available])
		],[
			AC_DEFINE(BPM_DRM_PAGEMAP_PUT_NOT_PRESENT, 1,
				[drm_pagemap_put() is not available])
		])
	])
])
