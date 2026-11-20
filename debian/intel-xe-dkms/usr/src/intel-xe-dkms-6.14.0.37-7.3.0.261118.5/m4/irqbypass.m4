dnl #
dnl # v6.17-2b521d86ee80
dnl # irqbypass: Take ownership of producer/consumer token tracking
dnl #
AC_DEFUN([AC_IRQ_BYPASS_REGISTER_PRODUCER_EVENTFD_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/irqbypass.h>
		],[
			struct irq_bypass_producer *producer = NULL;

			irq_bypass_register_producer(producer);
		],[
			AC_DEFINE([BPM_IRQ_BYPASS_REGISTER_PRODUCER_EVENTFD_NOT_PRESENT], 1,
				[irq_bypass_register_producer() does not have eventfd argument])
		],[
		])
	])
])

dnl #
dnl # v6.17-23b54381cee2
dnl # irqbypass: Require producers to pass in Linux IRQ number during registration
dnl #
AC_DEFUN([AC_IRQ_BYPASS_REGISTER_PRODUCER_IRQ_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/irqbypass.h>
			#include <linux/eventfd.h>
		],[
			struct irq_bypass_producer *producer = NULL;
			struct eventfd_ctx *eventfd = NULL;

			irq_bypass_register_producer(producer, eventfd);
		],[
			AC_DEFINE([BPM_IRQ_BYPASS_REGISTER_PRODUCER_IRQ_NOT_PRESENT], 1,
				[irq_bypass_register_producer() does not have irq argument])
		],[
		])
	])
])
