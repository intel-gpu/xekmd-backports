/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KUnit function redirection (static stubbing) API.
 *
 * Copyright (C) 2022, Google LLC.
 * Author: David Gow <davidgow@google.com>
 */

#ifndef _KUNIT_STATIC_STUB_H
#define _KUNIT_STATIC_STUB_H

#ifdef HAVE_KUNIT_STATIC_STUB_H
#include_next <kunit/static_stub.h>
#else
#define KUNIT_STATIC_STUB_REDIRECT(real_fn_name, args...) do {} while (0)
#endif

#if LINUX_VERSION_IS_GEQ(5,16,0)
#include_next <kunit/test.h>
#else
#include <linux/stddef.h>

struct kunit;

#ifndef kunit_get_current_test
static inline struct kunit *kunit_get_current_test(void)
{
        return NULL;
}
#endif

#ifndef kunit_fail_current_test
#define kunit_fail_current_test(fmt, ...) do {} while (0)
#endif

#endif /* < 5.16 */

#endif /* _KUNIT_STATIC_STUB_H */

