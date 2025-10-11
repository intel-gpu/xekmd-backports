dnl #
dnl # v6.13-908a1d775422
dnl # hrtimers: Introduce hrtimer_setup() to replace hrtimer_init()
dnl #
AC_DEFUN([AC_HRTIMER_SETUP_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/hrtimer.h>
                ],[
			struct hrtimer poll_check_timer;
			static enum hrtimer_restart xe_oa_poll_check_timer_cb(struct hrtimer *hrtimer);
			hrtimer_setup(&poll_check_timer, xe_oa_poll_check_timer_cb, 0, 0);
		],[
		],[
                        AC_DEFINE(BPM_HRTIMER_SETUP_NOT_PRESENT, 1,
                                [HRTIMER_SETUP macro is not avilable])
                ])
        ])
])
