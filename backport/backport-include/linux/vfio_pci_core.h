/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 */

#ifndef BACKPORT_VFIO_PCI_CORE_H
#define BACKPORT_VFIO_PCI_CORE_H

#include_next<linux/vfio_pci_core.h>
int vfio_pci_core_match_token_uuid(struct vfio_device *core_vdev,
				   const uuid_t *uuid);
#endif
