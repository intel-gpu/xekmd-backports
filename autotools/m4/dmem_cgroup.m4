dnl #
dnl #  v7.3 - dd517e49a312
dnl #  cgroup/dmem: Add queries for protection values
dnl #
dnl #  v7.3 - 34f3e2599253
dnl #  cgroup,cgroup/dmem: Add (dmem_)cgroup_common_ancestor helper
dnl #

AC_DEFUN([AC_DMEM_CGROUP_COMPAT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_CHECK_SYMBOL_EXPORT(
			[dmem_cgroup_below_min dmem_cgroup_below_low],
			[kernel/cgroup/dmem.c], [
		], [
			AC_DEFINE(BPM_DMEM_CGROUP_PROTECTION_NOT_EXPORTED, 1,
				  [Dmem cgroup protection queries are not exported])
		])
		AC_KERNEL_CHECK_SYMBOL_EXPORT([dmem_cgroup_get_common_ancestor],
			[kernel/cgroup/dmem.c], [
		], [
			AC_DEFINE(BPM_DMEM_CGROUP_ANCESTOR_NOT_EXPORTED, 1,
				  [Dmem cgroup common ancestor helper is not exported])
		])
	])
])
