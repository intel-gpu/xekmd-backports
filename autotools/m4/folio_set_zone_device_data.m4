dnl #
dnl #  v6.19 - 775465fd26a3
dnl #  lib/test_hmm: add zone device private THP test infrastructure
dnl #

AC_DEFUN([AC_FOLIO_SET_ZONE_DEVICE_DATA_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/memremap.h>
		], [
			struct folio *folio = NULL;

			folio_set_zone_device_data(folio, NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_SET_ZONE_DEVICE_DATA_NOT_PRESENT, 1,
				  [folio_set_zone_device_data() is not available])
		])
	])
])
