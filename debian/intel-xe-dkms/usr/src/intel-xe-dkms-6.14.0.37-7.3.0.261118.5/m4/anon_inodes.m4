dnl #
dnl # v6.10-55394d29c9e1
dnl # fs: Create anon_inode_getfile_fmode()
dnl #
AC_DEFUN([AC_ANON_INODE_GETFILE_FMODE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/anon_inodes.h>
		],[
			anon_inode_getfile_fmode(NULL, NULL, NULL, 0, 0);
		],[
		],[
			AC_DEFINE(BPM_ANON_INODE_GETFILE_FMODE_NOT_PRESENT, 1,
				[anon_inode_getfile_fmode() is not available])
		])
	])
])
