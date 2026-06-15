dnl #
dnl # v6.16-84798514db50
dnl # mm: Remove swap_writepage() and shmem_writepage()
dnl #
AC_DEFUN([AC_SHMEM_WRITEOUT_NOT_PRESENT], [
        AC_KERNEL_TRY_COMPILE([
                #include <linux/shmem_fs.h>
        ],[
		shmem_writeout(NULL, NULL, NULL);
        ],[
        ],[
                AC_DEFINE(BPM_SHMEM_WRITEOUT_NOT_PRESENT, 1,
                        [shmem_writeout is not available])
        ])
])
