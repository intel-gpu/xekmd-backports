dnl #
dnl #  v6.15 - 9ec84f79c5a7
dnl #  perf: Remove unnecessary parameter of security check
dnl #
dnl #  v7.3 - d32bf877c0c3
dnl #  perf/core: out-of-line and export perf_allow_cpu/tracepoint()
dnl #

AC_DEFUN([AC_PERF_ALLOW_CPU_COMPAT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE_SYMBOL([
			#include <linux/perf_event.h>
		], [
			(void)perf_allow_cpu();
		], [perf_allow_cpu], [kernel/events/core.c], [
		], [
			AC_DEFINE(BPM_PERF_ALLOW_CPU_NOT_PRESENT, 1,
				  [Exported no-argument perf_allow_cpu() is unavailable])
		])

		AC_KERNEL_TRY_COMPILE([
			#include <linux/perf_event.h>
		], [
			(void)perf_allow_kernel();
		], [
		], [
			AC_DEFINE(BPM_PERF_ALLOW_KERNEL_NO_ARGS_NOT_PRESENT, 1,
				  [perf_allow_kernel() requires an event attribute])
		])

		AC_KERNEL_CHECK_SYMBOL_EXPORT([perf_allow_kernel],
					     [kernel/events/core.c], [
		], [
			AC_DEFINE(BPM_PERF_ALLOW_KERNEL_NOT_EXPORTED, 1,
				  [perf_allow_kernel() is not exported to modules])
		])
	])
])
