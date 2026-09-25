/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2026 Intel Corporation
 */

#ifndef _XE_CPER_H_
#define _XE_CPER_H_

#include "abi/xe_sigid_abi.h"

struct pci_dev;
struct xe_ras_error_class;
struct xe_ras_get_counter_response;

#if IS_REACHABLE(CONFIG_UEFI_CPER_X86)
void xe_emit_hardware_error_cper(struct pci_dev *pdev, int cper_sev, enum xe_sigid sigid,
				 struct xe_ras_error_class *counter,
				 struct xe_ras_get_counter_response *response);
#else
static inline void xe_emit_hardware_error_cper(struct pci_dev *pdev, int cper_sev,
					       enum xe_sigid sigid,
					       struct xe_ras_error_class *counter,
					       struct xe_ras_get_counter_response *response) {}
#endif
#endif /* _XE_CPER_H_ */
