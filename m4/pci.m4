dnl #
dnl # v6.17-c42d50aefd17
dnl # mm: shrinker: add infrastructure for dynamically allocating shrinker
dnl #
AC_DEFUN([AC_PCI_IOV_VF_BAR_FUNCTIONS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			struct pci_dev *pdev = NULL;
			u32 sizes;
			sizes = pci_iov_vf_bar_get_sizes(pdev, 0, 1);
		],[
		],[
			AC_DEFINE([BPM_PCI_IOV_VF_BAR_FUNCTIONS_NOT_PRESENT], 1,
				[pci_iov_vf_bar_get_sizes and pci_iov_vf_bar_set_size functions not available])
		])
	])
])
