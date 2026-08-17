/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_MEI_UUID_H
#define _BACKPORT_LINUX_MEI_UUID_H

#ifdef BPM_LINUX_MEI_UUID_H_NOT_PRESENT
#include <linux/uuid.h>
#else
#include_next <linux/mei_uuid.h>
#endif

#ifdef BPM_UUID_LE_CMP_NOT_PRESENT
#ifndef uuid_le_cmp
#define uuid_le_cmp(u1, u2) memcmp(&(u1), &(u2), sizeof(uuid_le))
#endif
#endif

#endif /* _BACKPORT_LINUX_MEI_UUID_H */
