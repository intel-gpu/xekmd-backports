dnl #
dnl # v6.3-4d70c74659d9 
dnl # i915: Move list_count() to list.h as list_count_nodes() for broader use
dnl #
AC_DEFUN([AC_LIST_COUNT_NODES_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/list.h>
                ],[
			list_count_nodes(NULL);
                ],[
		],[
                        AC_DEFINE(BPM_LIST_COUNT_NODES_NOT_PRESENT, 1,
                                [list_count_nodes() is not available])
                ])
        ])
])
