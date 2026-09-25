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

void xe_ras_counter_threshold_crossed(struct xe_device *xe,
				      struct xe_sysctrl_event_response *response);
int xe_ras_get_counter(struct xe_device *xe, u8 severity, u8 component, u32 *value);
int xe_ras_clear_counter(struct xe_device *xe, u8 severity, u8 component);
int xe_ras_get_threshold(struct xe_device *xe, u8 severity, u8 component, u32 *threshold);
int xe_ras_set_threshold(struct xe_device *xe, u8 severity, u8 component, u32 threshold);
void xe_ras_init(struct xe_device *xe);
enum xe_ras_recovery_action xe_ras_process_errors(struct xe_device *xe);
int xe_ras_get_counter_response(struct xe_device *xe, struct xe_ras_error_class *counter,
				struct xe_ras_get_counter_response *out);
bool xe_ras_counter_is_valid(struct xe_device *xe, struct xe_ras_error_class *counter);
u32 xe_ras_drain_info_queue_raw(struct xe_device *xe,
				const struct xe_ras_get_counter_response *counter_resp,
				u8 *raw_buf, u32 raw_buf_size);

#endif
