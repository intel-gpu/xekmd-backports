dnl #
dnl # da0c02516c50 
dnl # mm/list_lru: simplify the list_lru walk callback function
dnl #

AC_DEFUN([AC_LIST_LRU_WALK_CB_PARAM_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/list_lru.h>
			static enum lru_status test_cb(struct list_head *item,
						   struct list_lru_one *list,
						   void *arg) {
				return LRU_REMOVED;
			}
		],[
			list_lru_walk_cb fn = test_cb;
			(void)fn;
		],[
		],[
			AC_DEFINE(BPM_LIST_LRU_WALK_CB_PARAM_NOT_PRESENT, 1,
				[Define if list_lru walk callback has no cb parameter])
		])
	])
])
