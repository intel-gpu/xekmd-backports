dnl #
dnl # Detect whether the target kernel has the i2c-designware Intel Xe
dnl # enablement (generic polling mode + poll-by-default when no IRQ +
dnl # parent-regmap quirk for "intel,xe-i2c").
dnl #
dnl # Support is detected as either:
dnl #   (a) mainline kernels v6.17+, which carry the feature natively, OR
dnl #   (b) backported (pre-v6.17) kernels that export
dnl #       __i2c_dw_read_intr_mask(), which is used as a feature marker
dnl #       indicating that the Intel Xe DesignWare I2C backport is present.
dnl #
dnl # The DesignWare changes are internal to the built-in driver and are
dnl # not otherwise visible to an out-of-tree module (no new UAPI, header
dnl # or Kconfig). The exported symbol is therefore used as the detection
dnl # mechanism. Its presence in Module.symvers is the signal; Module.symvers
dnl # is part of the linux-headers package, so no kernel source is required
dnl # on the target.
dnl #
dnl # If neither holds, xe_i2c is compiled out (BPM_XE_I2C_NOT_SUPPORTED) so
dnl # the Xe driver does not register the i2c_designware platform device,
dnl # which on an unpatched kernel would fail probe with
dnl # "IRQ index 0 not found" / "invalid resource" (KERN_ERR).
dnl #
AC_DEFUN([AC_XE_I2C_SUPPORTED], [
	AC_KERNEL_DO_BACKGROUND([
		xe_i2c_ok=no

		dnl (a) mainline v6.17+ already carries polling + Xe quirk natively
		AC_KERNEL_TRY_COMPILE([
			#include <linux/version.h>
			#if LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)
			#error kernel too old for native Xe i2c
			#endif
		], [], [xe_i2c_ok=yes], [])

		dnl (b) backported kernels export our dummy symbol; check Module.symvers
		dnl     only (empty file list = no source-grep fallback, no kernel source
		dnl     needed on the target).
		if test "x$xe_i2c_ok" != "xyes"; then
			AC_KERNEL_CHECK_SYMBOL_EXPORT([__i2c_dw_read_intr_mask], [],
				[xe_i2c_ok=yes], [])
		fi

		if test "x$xe_i2c_ok" != "xyes"; then
			AC_DEFINE(BPM_XE_I2C_NOT_SUPPORTED, 1,
				[i2c-designware lacks Intel Xe polling/quirk; disable xe_i2c])
		fi
	])
])
