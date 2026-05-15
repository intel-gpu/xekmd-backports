dnl #
dnl # v5.18-509853f9e1e7 
dnl # genirq: Provide generic_handle_irq_safe()
dnl #
AC_DEFUN([AC_GENERIC_HANDLE_IRQ_SAFE_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/irqdesc.h>
                ],[
			generic_handle_irq_safe(0);
                ],[
		],[
                        AC_DEFINE(BPM_GENERIC_HANDLE_IRQ_SAFE_NOT_PRESENT, 1,
                                [generic_handle_irq_safe() is not available])
                ])
        ])
])
