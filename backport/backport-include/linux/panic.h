/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_PANIC_H
#define _BACKPORT_PANIC_H

#include_next <linux/panic.h>

#ifndef TAINT_TEST
#define TAINT_TEST 18
#endif

#endif
