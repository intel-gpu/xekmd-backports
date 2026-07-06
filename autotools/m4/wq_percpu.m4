dnl #
dnl # c8272cfe36bd
dnl # workqueue: Add system_percpu_wq and system_dfl_wq
dnl #

AC_DEFUN([AC_WQ_PERCPU_NOT_PRESENT], [
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Werror"

    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
            [[
            #include <linux/workqueue.h>
            ]],
            [[
            unsigned int flags = WQ_PERCPU;
            ]]
        )],
        [
            AC_DEFINE(BPM_WQ_PERCPU_NOT_PRESENT, 0,
                [WQ_PERCPU flag is available])
        ],
        [
            AC_DEFINE(BPM_WQ_PERCPU_NOT_PRESENT, 1,
                [WQ_PERCPU flag is not available])
        ]
    )
])
