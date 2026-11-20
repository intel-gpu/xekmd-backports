dnl #
dnl # v5.18-a0386bba7093
dnl # spi: make remove callback a void function
dnl #
AC_DEFUN([AC_SPI_DRIVER_REMOVE_RETURN_VOID_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/spi/spi.h>
		], [
			void remove_cb(struct spi_device *spi);
			struct spi_driver sdrv = { .remove = remove_cb };
			(void)sdrv;
		], [
		], [
			AC_DEFINE([BPM_SPI_DRIVER_REMOVE_RETURN_VOID_NOT_PRESENT], 1,
				[spi_driver.remove callback returns int])
		])
	])
])
