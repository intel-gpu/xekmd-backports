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
                        AC_DEFINE(BPM_LIST_LRU_ADD_4ARGS_NOT_PRESENT, 1,
                                [Define to 1 if list_lru_add has 4 arguments])
                ])
        ])
])

dnl #
dnl # fb56fdf8b9a2
dnl # mm/list_lru: split the lock to per-cgroup scope
dnl #
AC_DEFUN([AC_LIST_LRU_ONE_LOCK_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/list_lru.h>
			#include <linux/spinlock.h>
		],[
			struct list_lru_one l;
			spin_lock(&l.lock);
		],[
			AC_DEFINE(BPM_LIST_LRU_ONE_LOCK_NOT_PRESENT, 1,
				[Define if struct list_lru_one has lock spinlock member])
		])
	])
])

dnl #
dnl # da0c02516c50
dnl # mm/list_lru: simplify the list_lru walk callback function
dnl #
AC_DEFUN([AC_LIST_LRU_WALK_CB_SIGNATURE_NOT_PRESENT], [
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
			AC_DEFINE(BPM_HAVE_LIST_LRU_WALK_CB_NOT_PRESENT, 1,
				[Define if list_lru walk callback has no spinlock parameter])
		])
	])
])

