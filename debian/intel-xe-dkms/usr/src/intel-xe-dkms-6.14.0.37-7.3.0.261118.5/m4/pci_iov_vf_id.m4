dnl #
dnl # v5.18-0e7df22401a3
dnl # PCI/IOV: Add pci_iov_vf_id() to get VF index
dnl #
AC_DEFUN([AC_PCI_IOV_VF_ID_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			struct pci_dev *dev = NULL;
			int id;
			id = pci_iov_vf_id(dev);
		],[
		],[
			AC_DEFINE([BPM_PCI_IOV_VF_ID_NOT_PRESENT], 1,
				[pci_iov_vf_id() function not available])
		])
	])
])
