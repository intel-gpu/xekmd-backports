/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BACKPORT_LINUX_WORDPART_H
#define _BACKPORT_LINUX_WORDPART_H

#ifdef HAVE_LINUX_WORDPART_H
#include_next <linux/wordpart.h>
#else
#include_next <linux/kernel.h>
#endif

#endif /* _BACKPORT_LINUX_WORDPART_H */
