dnl #
dnl # v6.15-4ba4f1afb6a9
dnl # perf: Generic hotplug support for a PMU with a scope
dnl #
AC_DEFUN([AC_PMU_SCOPE_MEMBER_NOT_PRESENT], [
       AC_KERNEL_DO_BACKGROUND([
               AC_KERNEL_TRY_COMPILE([
				#include <linux/perf_event.h>
                       ],[
				struct pmu test_pmu;
				test_pmu.scope = 0;
                       ],[
                       ],[
                               AC_DEFINE(BPM_PMU_SCOPE_MEMBER_NOT_PRESENT, 1,
                                       [struct pmu does not have scope member])
               ])
       ])
])
