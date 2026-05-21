dnl #
dnl # v6.15-888bd8322dfc
dnl # s390/pci: Introduce pdev->non_mappable_bars and replace VFIO_PCI_MMAP
dnl #
AC_DEFUN([AC_NON_MAPPABLE_BARS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			struct pci_dev *pdev = NULL;
			(void)sizeof(pdev->non_mappable_bars);
		],[
		],[
			AC_DEFINE([BPM_NON_MAPPABLE_BARS_NOT_PRESENT], 1,
				[struct pci_dev does not have non_mappable_bars member])
		])
	])
])
