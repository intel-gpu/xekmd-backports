dnl #
dnl # v6.19 - 5528fd38f230
dnl # PCI: Fix Resizable BAR restore order
dnl # 
AC_DEFUN([AC_PCI_RESIZE_RESOURCE_ARG4_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			struct pci_dev *pdev = NULL;
			int resno = 0;
			resource_size_t bar_size = 0;
			pci_resize_resource(pdev, resno, bar_size, 0);
		],[
		],[
			AC_DEFINE([BPM_PCI_RESIZE_RESOURCE_ARG4_NOT_PRESENT], 1,
				[pci_resize_resource() does not have 4th argument (exclude_bars)])
		])
	])
])

dnl #
dnl # bb1fabd0d94e
dnl # PCI: Add pci_rebar_size_supported() helper
dnl #
AC_DEFUN([AC_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			struct pci_dev *pdev = NULL;
			int bar = 0;
			int size = 0;
			pci_rebar_size_supported(pdev, bar, size);
		],[
		],[
			AC_DEFINE([BPM_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT], 1,
				[pci_rebar_size_supported() function not available])
		])
	])
])
dnl #
dnl # a33786988508
dnl # PCI: Move pci_rebar_size_to_bytes() and export it
dnl #
AC_DEFUN([AC_PCI_REBAR_SIZE_TO_BYTES_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			int size = 0;
			pci_rebar_size_to_bytes(size);
		],[
		],[
			AC_DEFINE([BPM_PCI_REBAR_SIZE_TO_BYTES_NOT_PRESENT], 1,
				[pci_rebar_size_to_bytes() function not available])
		])
	])
])

dnl #
dnl # 1c680f2acdbb
dnl # PCI: Add pci_rebar_get_max_size()
dnl #
AC_DEFUN([AC_PCI_REBAR_GET_MAX_SIZE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		],[
			struct pci_dev *pdev = NULL;
			int bar = 0;
			pci_rebar_get_max_size(pdev, bar);
		],[
		],[
			AC_DEFINE([BPM_PCI_REBAR_GET_MAX_SIZE_NOT_PRESENT], 1,
				[pci_rebar_get_max_size() function not available])
		])
	])
])
