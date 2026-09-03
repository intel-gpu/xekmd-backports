/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2026 Intel Corporation
 */

#ifndef _XE_RAS_H_
#define _XE_RAS_H_

#include <linux/types.h>
#include "xe_ras_types.h"

struct xe_device;
struct xe_sysctrl_event_response;

/* RAS disabled on old kernels lacking pci_clear_and_set_config_dword / DRM_WEDGE_RECOVERY_COLD_RESET */
static inline void xe_ras_counter_threshold_crossed(struct xe_device *xe,
					       struct xe_sysctrl_event_response *response) {}
static inline int xe_ras_get_counter(struct xe_device *xe, u8 severity, u8 component, u32 *value) { return -ENODEV; }
static inline int xe_ras_clear_counter(struct xe_device *xe, u8 severity, u8 component) { return 0; }
static inline int xe_ras_get_threshold(struct xe_device *xe, u8 severity, u8 component, u32 *threshold) { return -ENODEV; }
static inline int xe_ras_set_threshold(struct xe_device *xe, u8 severity, u8 component, u32 threshold) { return -ENODEV; }
static inline void xe_ras_init(struct xe_device *xe) {}
static inline enum xe_ras_recovery_action xe_ras_process_errors(struct xe_device *xe) { return XE_RAS_RECOVERY_ACTION_RECOVERED; }

#endif
