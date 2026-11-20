dnl
dnl # 56ef39899643
dnl # mm/memremap: add driver callback support for folio splitting
dnl
dnl

AC_DEFUN([AC_DEV_PAGEMAP_OPS_FOLIO_SPLIT_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/memremap.h>
                ],[
                        struct dev_pagemap_ops ops = {};
                        ops.folio_split(NULL, NULL);
                ],[
                ],[
                        AC_DEFINE(BPM_DEV_PAGEMAP_OPS_FOLIO_SPLIT_NOT_PRESENT, 1,
                                [folio_split callback not present in dev_pagemap_ops])
                ])
        ])
])

