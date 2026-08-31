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

dnl #
dnl # v7.0-rc1 - 83646541d197
dnl # drm/sched: Replace use of system_wq with system_percpu_wq
dnl #
dnl #
AC_DEFUN([AC_SYSTEM_PERCPU_WQ_NOT_PRESENT], [
        AC_KERNEL_TRY_COMPILE([
                #include <linux/workqueue.h>
        ],[
                struct workqueue_struct *wq = system_percpu_wq;
                (void)wq;
        ],[
        ],[
                AC_DEFINE(BPM_SYSTEM_PERCPU_WQ_NOT_PRESENT, 1,
                        [system_percpu_wq not available])
        ])
])

dnl #
dnl # v7.1 - 86898fa6b8cd
dnl # workqueue: Implement disable/enable for (delayed) work items
dnl #
AC_DEFUN([AC_DISABLE_DELAYED_WORK_SYNC_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/workqueue.h>
                ],[
                        struct delayed_work dwork;
                        bool ret;
                        ret = disable_delayed_work_sync(&dwork);
                        (void)ret;
                ],[
                ],[
                        AC_DEFINE(BPM_DISABLE_DELAYED_WORK_SYNC_NOT_PRESENT, 1,
                                [disable_delayed_work_sync is not declared in linux/workqueue.h])
                ])
        ])
])
