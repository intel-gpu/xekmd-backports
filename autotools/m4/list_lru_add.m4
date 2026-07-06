dnl #
dnl # 0a97c01cd20b 
dnl # list_lru: allow explicit memcg and NUMA node selection
dnl #
AC_DEFUN([AC_LIST_LRU_ADD_4ARGS_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
			#include <linux/list_lru.h>
                ],[
			struct list_lru lru;
			struct list_head item;
			int nid = 0;

			list_lru_add(&lru, &item, nid, NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT, 1,
                                [Define to 1 if list_lru_add does not have 4 arguments (nid, memcg)])
                ])
        ])
])
