/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_MUTEX_TYPES_H
#define __BACKPORT_MUTEX_TYPES_H

#ifdef HAVE_LINUX_MUTEX_TYPES_H
#include_next <linux/mutex_types.h
#else
#include <linux/mutex.h>
#endif

#endif
