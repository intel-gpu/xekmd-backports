dnl #
dnl # f6cfa602d2ba 
dnl # workqueue: replace use of system_unbound_wq with system_dfl_wq
dnl #

AC_DEFUN([AC_SYSTEM_DFL_WQ_NOT_PRESENT], [
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Werror"

    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
            [[
            #include <linux/workqueue.h>
            ]],
            [[
            struct workqueue_struct *wq = system_dfl_wq;
            ]]
        )],
        [
            AC_DEFINE(BPM_SYSTEM_DFL_WQ_NOT_PRESENT, 0,
                [system_dfl_wq is available])
        ],
        [
            AC_DEFINE(BPM_SYSTEM_DFL_WQ_NOT_PRESENT, 1,
                [system_dfl_wq is not available])
        ]
    )
])
