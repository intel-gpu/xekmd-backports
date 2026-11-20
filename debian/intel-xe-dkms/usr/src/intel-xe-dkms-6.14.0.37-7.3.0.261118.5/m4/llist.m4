dnl #
dnl # v6.7: d6b3358a2813
dnl # llist: add interface to check if a node is on a list
dnl #
AC_DEFUN([AC_INIT_LLIST_NODE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/llist.h>
		],[
			struct llist_node node;
			init_llist_node(&node);
		],[
			AC_DEFINE(BPM_INIT_LLIST_NODE_PRESENT, 1,
				[init_llist_node() is available, kernel >= 6.12])
		],[
			AC_DEFINE(BPM_INIT_LLIST_NODE_NOT_PRESENT, 1,
				[init_llist_node() is not available, kernel < 6.12])
		])
	])
])

