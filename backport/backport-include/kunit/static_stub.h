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

#endif /* _KUNIT_STATIC_STUB_H */

