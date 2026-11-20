dnl #
dnl # v6.15.10 - 86624ba3b522
dnl # vfio/pci: Do vf_token checks for VFIO_DEVICE_BIND_IOMMUFD
dnl #
AC_DEFUN([AC_MATCH_TOKEN_UUID_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/vfio.h>
		],[
			static const struct vfio_device_ops ops = {
				.match_token_uuid = NULL,
			};
			(void)ops;
		],[
		],[
			AC_DEFINE(BPM_MATCH_TOKEN_UUID_NOT_PRESENT, 1,
				[struct vfio_device_ops does not have match_token_uuid member])
		])
	])
])

