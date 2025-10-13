dnl #
dnl # v6.8-4edbd117ba3f
dnl # platform/x86/intel/vsec: Add intel_vsec_register
dnl #
AC_DEFUN([AC_INTEL_VSEC_REGISTER_NOT_PRESENT], [
        AC_KERNEL_CHECK_SYMBOL_EXPORT([intel_vsec_register],
                [drivers/platform/x86/intel/vsec.c], [INTEL_VSEC],
                [AC_DEFINE(BPM_INTEL_VSEC_REGISTER_NOT_PRESENT, 1,
                        [intel_vsec_register function not available])])
])
