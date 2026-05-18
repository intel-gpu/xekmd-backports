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
dnl # struct pci_driver::driver_managed_dma is not available on older kernels
dnl #
AC_DEFUN([AC_DRIVER_MANAGED_DMA_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			static struct pci_driver drv = {
				.driver_managed_dma = true,
			};
			(void)drv;
		],[
		],[
			AC_DEFINE([BPM_DRIVER_MANAGED_DMA_NOT_PRESENT], 1,
				[struct pci_driver does not have driver_managed_dma member])
		])
	])
])
