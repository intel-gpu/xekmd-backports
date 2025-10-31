dnl #
dnl # v6.16-8702048bb831
dnl # mm/kmap: Add kmap_local_page_try_from_panic()
dnl #
AC_DEFUN([AC_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/highmem-internal.h>
                ],[
			kmap_local_page_try_from_panic(NULL);
                ],[
		],[
                        AC_DEFINE(BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NOT_PRESENT, 1,
                                [kmap_local_page_try_from_panic function is not avilable])
                ])
        ])
])
