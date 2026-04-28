dnl #
dnl # v7.0-rc1 - 7b73c12c6ebf0
dnl # shmem: Add shmem_writeout()
dnl #
AC_DEFUN([AC_SHMEM_WRITEOUT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/shmem_fs.h>
                        #include <linux/swap.h>
                ],[
                        struct folio *folio = NULL;
                        int ret = shmem_writeout(folio, NULL, NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_SHMEM_WRITEOUT_NOT_PRESENT, 1,
                                [shmem_writeout is not available])
                ])
        ])
])
