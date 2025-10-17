dnl #
dnl # Test for alloc_ordered_workqueue_lockdep_map API availability
dnl # v6.12-34f50cc6441b
dnl # drm/sched: Use drm sched lockdep map for submit_wq
dnl #
AC_DEFUN([AC_ALLOC_ORDERED_WORKQUEUE_LOCKDEP_MAP_NOT_PRESENT], [
        AC_KERNEL_TRY_COMPILE([
                #include <linux/workqueue.h>
        ],[
                alloc_ordered_workqueue_lockdep_map("test", 0, NULL);
        ],[
        ],[
                AC_DEFINE(BPM_ALLOC_ORDERED_WORKQUEUE_LOCKDEP_MAP_NOT_PRESENT, 1,
                        [alloc_ordered_workqueue_lockdep_map not available])
        ])
])
