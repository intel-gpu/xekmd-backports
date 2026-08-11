/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_MEI_UUID_H
#define _BACKPORT_LINUX_MEI_UUID_H

#ifdef BPM_LINUX_MEI_UUID_H_NOT_PRESENT
#include <linux/uuid.h>
#else
#include_next <linux/mei_uuid.h>
#endif

#endif /* _BACKPORT_LINUX_MEI_UUID_H */
