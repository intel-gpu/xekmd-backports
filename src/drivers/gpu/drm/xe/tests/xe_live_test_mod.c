// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright © 2023 Intel Corporation
 */
#include <linux/module.h>
#include <kunit/test.h>

extern struct kunit_suite xe_bo_test_suite;
extern struct kunit_suite xe_bo_shrink_test_suite;
extern struct kunit_suite xe_dma_buf_test_suite;
extern struct kunit_suite xe_migrate_test_suite;
extern struct kunit_suite xe_mocs_test_suite;

kunit_test_suite(xe_bo_test_suite);
kunit_test_suite(xe_bo_shrink_test_suite);
kunit_test_suite(xe_dma_buf_test_suite);
kunit_test_suite(xe_migrate_test_suite);
kunit_test_suite(xe_mocs_test_suite);

#if IS_ENABLED(CPTCFG_PRELIM_DRM_XE_EUDEBUG)
extern struct kunit_suite xe_eudebug_test_suite;
kunit_test_suite(xe_eudebug_test_suite);
#endif

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("xe live kunit tests");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
