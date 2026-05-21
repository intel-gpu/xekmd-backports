/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_KERNEL_SPRINTF_H_
#define _BACKPORT_LINUX_KERNEL_SPRINTF_H_

#ifdef HAVE_LINUX_SPRINTF_H
#include_next <linux/sprintf.h>
#else
#include_next <linux/kernel.h>
#endif

#endif
