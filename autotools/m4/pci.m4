dnl #
dnl # v6.17-84f890414a12
dnl # PCI/IOV: Allow drivers to control VF BAR size
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

dnl #
dnl # v5.18-a7e9f240c0da
dnl # PCI/IOV: Add pci_iov_get_pf_drvdata() to allow VF reaching the drvdata of a PF
AC_DEFUN([AC_PCI_IOV_GET_PF_DRVDATA_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/pci.h>
                ],[
                        struct pci_dev *dev = NULL;
			struct pci_driver *pf_driver = NULL;
			pci_iov_get_pf_drvdata(dev, pf_driver);
                ],[
                ],[
                        AC_DEFINE([BPM_PCI_IOV_GET_PF_DRVDATA_NOT_PRESENT], 1,
                                [pci_iov_get_pf_drvdata() function not available])
                ])
        ])
])
