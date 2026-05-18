/* SPDX-License-Identifier: GPL-2.0 */
/*
 *	PCI Class, Vendor and Device IDs
 *
 *	Please keep sorted by numeric Vendor ID and Device ID.
 *
 *	Do not add new entries to this file unless the definitions
 *	are shared between multiple drivers.
 */
#ifndef _BACKPORT_PCI_IDS_H
#define _BACKPORT_PCI_IDS_H

#include_next <linux/pci_ids.h>

#ifndef PCI_DEVICE_ID_INTEL_DSA_SPR0
#define PCI_DEVICE_ID_INTEL_DSA_SPR0 0x0b25
#endif

#ifndef PCI_DEVICE_ID_INTEL_IAX_SPR0
#define PCI_DEVICE_ID_INTEL_IAX_SPR0 0x0cfe
#endif

#endif