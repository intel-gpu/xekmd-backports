dnl #
dnl # v5.15.200-21ca3ee3f6fa
dnl # timers: Split [try_to_]del_timer[_sync]() to prepare for shutdown mode
dnl #
AC_DEFUN([AC_TIMER_DELETE_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/timer.h>
                ],[
                        struct timer_list timer;

                        timer_delete(&timer);
                ],[
                ],[
                        AC_DEFINE(BPM_TIMER_DELETE_NOT_PRESENT, 1,
                                [timer_delete() function is not available])
                ])
        ])
])
