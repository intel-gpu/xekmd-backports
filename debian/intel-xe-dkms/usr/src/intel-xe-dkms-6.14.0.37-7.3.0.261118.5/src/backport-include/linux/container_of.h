/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_CONTAINER_OF_H
#define __BACKPORT_LINUX_CONTAINER_OF_H

#ifdef HAVE_LINUX_CONTAINER_OF_H
#include_next <linux/container_of.h>
#else
#include_next <linux/kernel.h>
#endif

#endif /* __BACKPORT_LINUX_CONTAINER_OF_H */
