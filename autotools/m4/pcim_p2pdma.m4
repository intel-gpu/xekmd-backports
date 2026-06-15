dnl #
dnl # v6.19-372d6d1b8ae3
dnl # PCI/P2PDMA: Refactor to separate core P2P functionality from memory allocation
dnl #
AC_DEFUN([AC_PCIM_P2PDMA_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			struct pci_dev *pdev = NULL;
			int ret;
			ret = pcim_p2pdma_init(pdev);
		],[
		],[
			AC_DEFINE([BPM_PCIM_P2PDMA_NOT_PRESENT], 1,
				[pcim_p2pdma_init() and pcim_p2pdma_provider() functions not available])
		])
	])
])
