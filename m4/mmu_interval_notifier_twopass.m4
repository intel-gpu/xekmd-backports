dnl #
dnl # 7aba71dbc416
dnl # mm/mmu_notifier: Allow two-pass struct mmu_interval_notifiers
dnl #

AC_DEFUN([AC_MMU_INTERVAL_NOTIFIER_TWOPASS_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                    #include <linux/mmu_notifier.h>
                ],[
                       struct mmu_interval_notifier_ops ops = {
                               .invalidate_start = NULL,
                               .invalidate_finish = NULL,
                       };
                ],[
                ],[
                       AC_DEFINE(BPM_MMU_INTERVAL_NOTIFIER_TWOPASS_NOT_PRESENT, 1,
                            [Define to 1 if mmu_interval_notifier_ops lacks two-pass invalidate callbacks])
                ])
        ])
])
