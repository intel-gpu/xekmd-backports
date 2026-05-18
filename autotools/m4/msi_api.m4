dnl #
dnl # v6.2 - 34026364df8e
dnl # PCI/MSI: Provide post-enable dynamic allocation interfaces for MSI-X
dnl #
AC_DEFUN([AC_PCI_MSIX_ALLOC_IRQ_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
			#include <linux/msi.h>
		],[
			struct pci_dev *dev = NULL;
			bool ret;
			ret = pci_msix_can_alloc_dyn(dev);
		],[
		],[
			AC_DEFINE([BPM_PCI_MSIX_ALLOC_IRQ_NOT_PRESENT], 1,
				[pci_msix_can_alloc_dyn/pci_msix_alloc_irq_at/irq_domain_instantiate not available])
		])
	])
])
