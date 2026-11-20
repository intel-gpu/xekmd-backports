/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_INTEL_VSEC_H
#define _BACKPORT_INTEL_VSEC_H

#include_next <linux/intel_vsec.h>
#include <linux/module.h>

#ifdef BPM_MODULE_IMPORT_TO_STRING_LITERAL_PRESENT
MODULE_IMPORT_NS(INTEL_VSEC);
#else
MODULE_IMPORT_NS("INTEL_VSEC");
#endif

#endif /* _BACKPORT_INTEL_VSEC_H */
