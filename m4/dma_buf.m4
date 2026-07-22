dnl #
dnl # 95308225e5ba
dnl # dma-buf: Rename dma_buf_move_notify() to dma_buf_invalidate_mappings()
dnl #

AC_DEFUN([AC_DMA_BUF_INVALIDATE_MAPPINGS_NOT_PRESENT], [
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Werror"

    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
            [[
            #include <linux/dma-buf.h>
            ]],
            [[
            struct dma_buf *buf = NULL;
            dma_buf_invalidate_mappings(buf);
            ]]
        )],
        [
        ],
        [
            AC_DEFINE(BPM_DMA_BUF_INVALIDATE_MAPPINGS_NOT_PRESENT, 1,
                [dma_buf_invalidate_mappings() is not available])
        ]
    )
])

dnl #
dnl # ef246da8e63c
dnl # dma-buf: Rename .move_notify() callback to a clearer identifier
dnl #

AC_DEFUN([AC_DMA_BUF_ATTACH_OPS_INVALIDATE_MAPPINGS_NOT_PRESENT], [
    EXTRA_CFLAGS="$EXTRA_CFLAGS -Werror"

    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
            [[
            #include <linux/dma-buf.h>
            ]],
            [[
            struct dma_buf_attach_ops ops = {
                .invalidate_mappings = NULL
            };
            ]]
        )],
        [
        ],
        [
            AC_DEFINE(BPM_DMA_BUF_ATTACH_OPS_INVALIDATE_MAPPINGS_NOT_PRESENT, 1,
                [dma_buf_attach_ops has no invalidate_mappings member])
        ]
    )
])