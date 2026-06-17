dnl #
dnl # v6.4-8fc4fddaf9a1
dnl # locking/generic: Wire up local{,64}_try_cmpxchg()
dnl #
AC_DEFUN([AC_LOCAL64_TRY_CMPXCHG_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <asm-generic/local64.h>
                ],[
			local64_try_cmpxchg(NULL, NULL, 0);
                ],[
		],[
                        AC_DEFINE(BPM_LOCAL64_TRY_CMPXCHG_NOT_PRESENT, 1,
                                [local64_try_cmpxchg is not available])
                ])
        ])
])
