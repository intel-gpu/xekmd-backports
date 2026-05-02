dnl #
dnl # v6.17-2b521d86ee80
dnl # irqbypass: Take ownership of producer/consumer token tracking
dnl #
AC_DEFUN([AC_IRQ_BYPASS_REGISTER_PRODUCER_ARG3_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/irqbypass.h>
			#include <linux/eventfd.h>
		],[
			struct irq_bypass_producer *producer = NULL;
			struct eventfd_ctx *eventfd = NULL;

			irq_bypass_register_producer(producer, eventfd, 0);
		],[
		],[
			AC_DEFINE([BPM_IRQ_BYPASS_REGISTER_PRODUCER_ARG3_NOT_PRESENT], 1,
				[irq_bypass_register_producer() does not have eventfd and irq arguments])
		])
	])
])
