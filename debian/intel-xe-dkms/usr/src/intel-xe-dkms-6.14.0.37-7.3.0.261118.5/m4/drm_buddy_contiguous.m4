dnl #
dnl # dc2fc00ba94de
dnl # drm/xe: Use DRM_BUDDY_CONTIGUOUS_ALLOCATION for contiguous allocations
dnl #
AC_DEFUN([AC_DRM_BUDDY_CONTIGUOUS_ALLOCATION_NOT_PRESENT], [
                AC_KERNEL_DO_BACKGROUND([
                        AC_KERNEL_TRY_COMPILE([
                                #include <drm/drm_buddy.h>
                        ],[
                                unsigned long flags = DRM_BUDDY_CONTIGUOUS_ALLOCATION;
                                (void)flags;
                        ],[
                        ],[
                                AC_DEFINE(BPM_DRM_BUDDY_CONTIGUOUS_ALLOCATION_NOT_PRESENT, 1,
                                [Neither GPU_BUDDY_CONTIGUOUS_ALLOCATION nor DRM_BUDDY_CONTIGUOUS_ALLOCATION is present])
                        ])
                ])
])
