dnl #
dnl # v6.16-8702048bb831
dnl # mm/kmap: Add kmap_local_page_try_from_panic()
dnl #
AC_DEFUN([AC_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/highmem.h>
                ],[
                        kmap_local_page_try_from_panic((const struct page *)NULL);
                ],[
                        dnl const-arg version present; check if non-const also compiles
                        AC_KERNEL_TRY_COMPILE([
                                #include <linux/highmem.h>
                        ],[
                                kmap_local_page_try_from_panic((struct page *)NULL);
                        ],[
                                AC_DEFINE(BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NONCONST_PRESENT, 1,
                                        [kmap_local_page_try_from_panic exists but takes non-const struct page *])
                        ],[
                                dnl const-only version present (>= v6.16); no backport define needed
                        ])
                ],[
                        dnl const-arg version not present; try non-const variant
                        AC_KERNEL_TRY_COMPILE([
                                #include <linux/highmem.h>
                        ],[
                                kmap_local_page_try_from_panic((struct page *)NULL);
                        ],[
                                AC_DEFINE(BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NONCONST_PRESENT, 1,
                                        [kmap_local_page_try_from_panic exists but takes non-const struct page *])
                        ],[
                                dnl function entirely absent (< v6.16)
                                AC_DEFINE(BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NOT_PRESENT, 1,
                                        [kmap_local_page_try_from_panic is not available])
                        ])
                ])
        ])
])
