dnl #
dnl # Detect whether the target kernel has the i2c-designware Intel Xe
dnl # enablement (generic polling mode + poll-by-default when no IRQ +
dnl # parent-regmap quirk for "intel,xe-i2c").
dnl #
dnl # Support is detected as either:
dnl #   (a) mainline kernels v6.17+, which carry the feature natively, OR
dnl #   (b) backported (pre-v6.17) kernels that export the dummy symbol
dnl #       i2c_designware_xe_backport from the built-in i2c-designware platform
dnl #       driver. These internal driver changes are not otherwise visible to
dnl #       an out-of-tree module (no new export, header or Kconfig), so the
dnl #       dummy symbol is used. Its presence in Module.symvers is the signal;
dnl #       Module.symvers is part of the linux-headers package, so no kernel
dnl #       source is required on the target.
dnl #
dnl # If neither holds, xe_i2c is compiled out (BPM_XE_I2C_NOT_SUPPORTED) so
dnl # the Xe driver does not register the i2c_designware platform device, which
dnl # on an unpatched kernel would fail probe with "IRQ index 0 not found" /
dnl # "invalid resource" (KERN_ERR).
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
			AC_KERNEL_CHECK_SYMBOL_EXPORT([i2c_designware_xe_backport], [],
				[xe_i2c_ok=yes], [])
		fi

		if test "x$xe_i2c_ok" != "xyes"; then
			AC_DEFINE(BPM_XE_I2C_NOT_SUPPORTED, 1,
				[i2c-designware lacks Intel Xe polling/quirk; disable xe_i2c])
		fi
	])
])
