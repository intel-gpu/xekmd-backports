dnl # pci_rebar.m4 - check for v7.0 pci rebar helpers
AC_DEFUN([AC_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
#include <linux/pci.h>
		], [
			bool (*fn)(struct pci_dev *, int, int) = pci_rebar_size_supported;
			(void)fn;
		], [
		], [
			AC_DEFINE(BPM_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT, 1,
			[pci_rebar_size_supported and related helpers not available])
		])
	])
])

dnl #
dnl # v7.1.4.6 - 51b254181df2
dnl # PCI: Move Resizable BAR code to rebar.c
dnl #
AC_DEFUN([AC_PCI_RESIZE_RESOURCE_VF_BARS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pci.h>
		], [
			int (*fn)(struct pci_dev *, int, int, int) = pci_resize_resource;
			(void)fn;
		], [
		], [
			AC_DEFINE(BPM_PCI_RESIZE_RESOURCE_VF_BARS_NOT_PRESENT, 1,
			[pci_resize_resource does not take exclude_bars 4th argument])
		])
	])
])
