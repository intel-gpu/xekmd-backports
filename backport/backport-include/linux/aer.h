/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_AER_H
#define _BACKPORT_LINUX_AER_H

#include_next <linux/aer.h>
#include <linux/module.h>

#ifdef BPM_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT
MODULE_IMPORT_NS(CXL);
#else
MODULE_IMPORT_NS("CXL");
#endif

#endif /* _BACKPORT_LINUX_AER_H */
