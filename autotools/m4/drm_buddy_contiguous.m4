dnl #
dnl # Check if DRM_BUDDY_CONTIGUOUS_ALLOCATION is defined in drm_buddy.h
dnl #
AC_DEFUN([AC_DRM_BUDDY_CONTIGUOUS_ALLOCATION_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <drm/drm_buddy.h>
                ],[
                        unsigned long flags = DRM_BUDDY_CONTIGUOUS_ALLOCATION;
                        (void)flags;
                ],[
                        AC_DEFINE(BPM_DRM_BUDDY_CONTIGUOUS_ALLOCATION_PRESENT, 1,
                                [DRM_BUDDY_CONTIGUOUS_ALLOCATION is defined in drm_buddy.h])
                ])
        ])
])
