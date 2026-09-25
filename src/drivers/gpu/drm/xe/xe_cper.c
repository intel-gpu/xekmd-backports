// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/bcd.h>
#include <linux/pci.h>

#include <drm/drm_print.h>

#include "regs/xe_regs.h"
#include "xe_cper.h"
#include "xe_cper_types.h"
#include "xe_device.h"
#include "xe_mmio.h"
#include "xe_printk.h"
#include "xe_ras.h"
#include "xe_ras_types.h"
#include "xe_trace_cper.h"

static const struct xe_platform_id_entry xe_platform_ids[] = {
	/* 0x674C  platform/8086:674c */
	{ 0x674C, GUID_INIT(0x9046afe5, 0x9041, 0x5124,
			    0x86, 0x14, 0x92, 0x55, 0x0d, 0x9e, 0x9d, 0xa6) },
};

static const guid_t *lookup_platform_id(const struct pci_dev *pdev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(xe_platform_ids); i++)
		if (xe_platform_ids[i].device_id == pdev->device)
			return &xe_platform_ids[i].platform_id;
	return NULL;
}

static u64 cper_timestamp_now(void)
{
	struct tm tm;
	u64 ts = 0;
	u8 *p = (u8 *)&ts;
	int year;

	time64_to_tm(ktime_get_real_seconds(), 0, &tm);

	year = tm.tm_year + 1900;

	p[0] = bin2bcd(tm.tm_sec);
	p[1] = bin2bcd(tm.tm_min);
	p[2] = bin2bcd(tm.tm_hour);
	p[3] = 0x1; /* precise time */
	p[4] = bin2bcd(tm.tm_mday);
	p[5] = bin2bcd(tm.tm_mon + 1);
	p[6] = bin2bcd(year % 100);
	p[7] = bin2bcd(year / 100);

	return ts;
}

static guid_t read_fru_id(struct xe_device *xe)
{
	struct xe_mmio *mmio = xe_root_tile_mmio(xe);
	guid_t guid = GUID_INIT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	u64 val;

	val = xe_mmio_read64_2x32(mmio, CRI_DEVICE_UID);

	memcpy(&guid, &val, sizeof(val));

	return guid;
}

static void fill_fw_id(struct xe_device *xe, struct xe_cper_sec_intel_err_hdr *ihdr)
{
	/* TODO: populate ihdr->fw_id from firmware version queries */
}

static void xe_cper_init_intel_err_hdr(struct xe_device *xe, const u8 location[12],
				       u64 first_timestamp, u32 sig_id, u32 error_count,
				       struct xe_cper_sec_intel_err_hdr *ihdr)
{
	if (location) {
		memcpy(&ihdr->error_class, location, sizeof(ihdr->error_class));
		ihdr->validation_bits |= XE_CPER_VALID_LOCATION;
	}

	if (first_timestamp) {
		ihdr->first_timestamp = first_timestamp;
		ihdr->validation_bits |= XE_CPER_VALID_FIRST_TIMESTAMP;
	}

	if (sig_id != U32_MAX) {
		ihdr->sig_id = sig_id;
		ihdr->validation_bits |= XE_CPER_VALID_SIG_ID;
	}

	ihdr->error_count = error_count;

	strscpy(ihdr->pci_bdf, pci_name(to_pci_dev(xe->drm.dev)), sizeof(ihdr->pci_bdf));
	ihdr->validation_bits |= XE_CPER_VALID_PCI_BDF;

#ifdef MODULE
	if (THIS_MODULE->srcversion) {
		strscpy(ihdr->drv_version, THIS_MODULE->srcversion, sizeof(ihdr->drv_version));
		ihdr->validation_bits |= XE_CPER_VALID_DRV_VERSION;
	}
#endif

	fill_fw_id(xe, ihdr);
}

static void xe_cper_record_emit(struct xe_device *xe, u8 severity,
				guid_t *notification_type,
				struct xe_cper_sec_intel_err_hdr *ihdr,
				const void *einfo, u32 einfo_len)
{
	struct pci_dev *pdev = to_pci_dev(xe->drm.dev);
	const guid_t *platform_id = lookup_platform_id(pdev);
	u32 total_len = sizeof(struct xe_cper_nonstd_record) + einfo_len;
	struct cper_section_descriptor *sdesc;
	struct cper_record_header *rhdr;
	struct xe_cper_nonstd_record *rec;

	rec = kzalloc(total_len, GFP_KERNEL);
	if (!rec)
		return;

	rhdr  = &rec->record_hdr;
	sdesc = &rec->section_desc;

	/* Assemble the CPER record header (UEFI Appendix N.2.1) */
	memcpy(rhdr->signature, CPER_SIG_RECORD, CPER_SIG_SIZE);
	rhdr->revision          = CPER_RECORD_REV;
	rhdr->signature_end     = CPER_SIG_END;
	rhdr->section_count     = 1;
	rhdr->error_severity    = severity;
	rhdr->validation_bits   = CPER_VALID_TIMESTAMP;
	rhdr->record_length     = total_len;
	rhdr->timestamp         = cper_timestamp_now();
	if (platform_id) {
		rhdr->platform_id      = *platform_id;
		rhdr->validation_bits |= CPER_VALID_PLATFORM_ID;
	}
	rhdr->creator_id        = INTEL_CPER_CREATOR_XEKMD;
	rhdr->notification_type = *notification_type;
	rhdr->record_id         = cper_next_record_id();
	rhdr->flags             = 0;

	/* Assemble the section descriptor (UEFI Appendix N.2.2) */
	sdesc->section_offset   = sizeof(struct cper_record_header) +
				  sizeof(struct cper_section_descriptor);
	sdesc->section_length   = sizeof(struct xe_cper_sec_intel_err_hdr) + einfo_len;
	sdesc->revision         = CPER_RECORD_REV;
	/*
	 * Set validation_bits using CPER_SEC_VALID_FRU_ID / CPER_SEC_VALID_FRU_TEXT
	 * when the corresponding fields are populated.
	 */
	sdesc->validation_bits  = 0;
	sdesc->reserved         = 0;
	sdesc->flags            = 0;
	sdesc->section_type     = INTEL_CPER_SECTION_ACCEL_GENERIC;
	sdesc->fru_id = read_fru_id(xe);
	sdesc->validation_bits |= CPER_SEC_VALID_FRU_ID;
	sdesc->section_severity = severity;

	/* Copy the Intel-specific section header (updated with BDF/version) */
	rec->intel_hdr = *ihdr;

	/* Append optional variable-length error info */
	if (einfo && einfo_len)
		memcpy((u8 *)rec + sizeof(*rec), einfo, einfo_len);

	trace_xe_error_cper(xe, &rhdr->platform_id, &sdesc->fru_id, severity,
			    &rec->intel_hdr, total_len, (u8 *)rec);

	kfree(rec);
}

/**
 * struct xe_cper_einfo_entry - One CPER error-info buffer with its byte size
 * @hdr: dynamic-counter header carrying the per-entry error_class and counter
 *       value; used by the caller to build a dedicated xe_cper_sec_intel_err_hdr
 *       for each CPER record
 * @einfo: allocated error-info payload (caller must kfree)
 * @einfo_size: byte size of @einfo including any event_queue data
 * @timestamp: timestamp of first occurrence of dynamic-counter
 */
struct xe_cper_einfo_entry {
	struct xe_ras_info_queue_dynamic_counter_hdr hdr;
	struct xe_cper_sec_intel_error_info *einfo;
	u32 einfo_size;
	u64 timestamp;
};

static void fill_einfo_error_class(struct xe_cper_sec_intel_error_info *einfo,
				   const struct xe_ras_error_class *ec)
{
	einfo->error_class.error_type      = ec->common.severity;
	einfo->error_class.error_component = ec->common.component;
	einfo->error_class.tile            = ec->product.unit.tile;
	einfo->error_class.instance        = ec->product.unit.instance;
	einfo->error_class.cause           = ec->product.cause.cause;
}

static struct xe_cper_sec_intel_error_info *
build_einfo(const struct xe_ras_error_log *logs, u32 num_logs,
	    const struct xe_ras_error_class *ec, u32 error_count,
	    u32 *size_out, u64 *ts_out)
{
	/*
	 * Although xe_intel_priv_event_entry has a flexible metadata[] array,
	 * every entry we emit carries the fixed-length error_details payload
	 * from xe_ras_error_log, so the per-entry stride is constant here.
	 */
	u32 entry_size = offsetof(struct xe_intel_priv_event_entry, metadata) +
			 sizeof_field(struct xe_ras_error_log, error_details);
	struct xe_cper_sec_intel_error_info *einfo;
	struct xe_intel_priv_event_entry *entry;
	u32 einfo_size = sizeof(*einfo) + num_logs * entry_size;
	u32 i;

	einfo = kzalloc(einfo_size, GFP_KERNEL);
	if (!einfo)
		return NULL;

	einfo->error_count        = error_count;
	einfo->event_queue_length = num_logs * entry_size;
	einfo->event_queue_count  = num_logs;
	fill_einfo_error_class(einfo, ec);

	entry = (struct xe_intel_priv_event_entry *)einfo->event_queue;
	for (i = 0; i < num_logs; i++) {
		entry->entry_length = sizeof_field(struct xe_ras_error_log, error_details);
		entry->timestamp    = logs[i].timestamp;
		memcpy(entry->metadata, logs[i].error_details, sizeof(logs[i].error_details));
		entry = (struct xe_intel_priv_event_entry *)((u8 *)entry + entry_size);
	}

	*size_out = einfo_size;
	*ts_out   = logs[0].timestamp;
	return einfo;
}

static void free_einfo_arr(struct xe_cper_einfo_entry *einfo_arr, u32 count)
{
	u32 i;

	if (!einfo_arr)
		return;

	for (i = 0; i < count; i++)
		kfree(einfo_arr[i].einfo);
	kfree(einfo_arr);
}

/**
 * xe_prepare_cper_error_info - Build the CPER error info records from RAS info queue data
 * @xe: xe device instance
 * @counter_resp: counter response containing the first embedded chunk
 * @error_class: RAS error class used to populate the einfo error_class fields
 * @einfo_size_out: output size of the allocated einfo buffer
 *
 * Assembles the complete raw info queue data from the first chunk already
 * embedded in @counter_resp and any additional chunks fetched via
 * GET_INFO_QUEUE_DATA.  Two use cases are supported based on num_headers in
 * the info queue header:
 *
 * Detail error counter (num_headers == 0)::
 *
 *   [xe_ras_error_log * N]
 *
 *   Returns one xe_cper_einfo_entry covering all N logs.
 *
 * Aggregate error counter (num_headers > 0)::
 *
 *   [xe_ras_info_queue_dynamic_counter_hdr * num_headers]
 *   [xe_ras_error_log * N]
 *
 *   Returns one xe_cper_einfo_entry per header.  Each header's @counter field
 *   gives the number of consecutive xe_ras_error_log entries belonging to it
 *   and its @error_class is used to populate the entry's einfo->error_class.
 *
 * Returns: allocated xe_cper_einfo_entry array on success (caller must kfree
 *          each entry's einfo then kfree the array), NULL on failure.
 *          @count_out is set to the number of entries in the array.
 */
static struct xe_cper_einfo_entry *
xe_prepare_cper_error_info(struct xe_device *xe,
			   const struct xe_ras_get_counter_response *counter_resp,
			   const struct xe_ras_error_class *error_class,
			   u32 *count_out)
{
	const struct xe_ras_info_queue_header *first_qhdr =
		&counter_resp->info_queue.queue_header;
	struct xe_cper_einfo_entry *einfo_arr;
	u32 num_headers, headers_size;
	u32 raw_total;
	u8 *raw_buf;
	u32 i;

	raw_buf = kzalloc(XE_RAS_INFO_QUEUE_MAX_TOTAL_SIZE, GFP_KERNEL);
	if (!raw_buf)
		return NULL;

	raw_total = xe_ras_drain_info_queue_raw(xe, counter_resp, raw_buf,
						XE_RAS_INFO_QUEUE_MAX_TOTAL_SIZE);
	if (!raw_total) {
		kfree(raw_buf);
		return NULL;
	}

	num_headers  = first_qhdr->num_headers;
	headers_size = num_headers * sizeof(struct xe_ras_info_queue_dynamic_counter_hdr);

	if (headers_size > raw_total) {
		xe_warn(xe, "[RAS]: CPER: aggregate headers size (%u) exceeds raw total (%u)\n",
			headers_size, raw_total);
		kfree(raw_buf);
		return NULL;
	}

	if (num_headers == 0) {
		/* Detailed counter case: single einfo covering all log entries */
		u32 num_logs = raw_total / sizeof(struct xe_ras_error_log);
		const struct xe_ras_error_log *logs =
			(const struct xe_ras_error_log *)raw_buf;
		struct xe_cper_sec_intel_error_info *einfo;

		if (!num_logs) {
			kfree(raw_buf);
			return NULL;
		}

		einfo_arr = kzalloc_objs(*einfo_arr, 1, GFP_KERNEL);
		if (!einfo_arr) {
			kfree(raw_buf);
			return NULL;
		}

		einfo = build_einfo(logs, num_logs, error_class, counter_resp->value,
				    &einfo_arr[0].einfo_size, &einfo_arr[0].timestamp);
		if (!einfo) {
			kfree(einfo_arr);
			kfree(raw_buf);
			return NULL;
		}

		einfo_arr[0].hdr.error_class = *error_class;
		einfo_arr[0].hdr.counter     = counter_resp->value;
		einfo_arr[0].einfo           = einfo;
		*count_out = 1;

	} else {
		/* Aggregate conter case: one einfo per dynamic-counter header */
		const struct xe_ras_info_queue_dynamic_counter_hdr *hdrs =
			(const struct xe_ras_info_queue_dynamic_counter_hdr *)raw_buf;
		const struct xe_ras_error_log *all_logs =
			(const struct xe_ras_error_log *)(raw_buf + headers_size);
		u32 avail_logs = (raw_total - headers_size) / sizeof(struct xe_ras_error_log);
		u32 log_offset = 0;
		u32 einfo_count = 0;

		einfo_arr = kzalloc_objs(*einfo_arr, num_headers, GFP_KERNEL);
		if (!einfo_arr) {
			kfree(raw_buf);
			return NULL;
		}

		for (i = 0; i < num_headers; i++) {
			u32 num_logs = min_t(u32, hdrs[i].counter, XE_RAS_NUM_COUNTERS);
			struct xe_cper_sec_intel_error_info *einfo;

			if (log_offset + num_logs > avail_logs) {
				xe_warn(xe, "[RAS]: CPER: header[%u] claims %u logs but only %u remain\n",
					i, num_logs, avail_logs - log_offset);
				break;
			}

			if (!num_logs)
				continue;

			einfo = build_einfo(&all_logs[log_offset], num_logs,
					    &hdrs[i].error_class, num_logs,
					    &einfo_arr[einfo_count].einfo_size,
					    &einfo_arr[einfo_count].timestamp);
			if (!einfo) {
				free_einfo_arr(einfo_arr, einfo_count);
				kfree(raw_buf);
				return NULL;
			}

			einfo_arr[einfo_count].hdr   = hdrs[i];
			einfo_arr[einfo_count].einfo = einfo;
			log_offset += num_logs;
			einfo_count++;
		}

		*count_out = einfo_count;
	}

	kfree(raw_buf);
	return einfo_arr;
}

/**
 * xe_emit_hardware_error_cper() - Emit a hardware error CPER record
 * @pdev: PCI device associated with the Xe device
 * @cper_sev: CPER severity
 * @sigid: Error signature identifier
 * @error_class: Hardware error classification details
 * @response: Response of get counter
 *
 * Emit a CPER record for a hardware error
 */
void xe_emit_hardware_error_cper(struct pci_dev *pdev, int cper_sev, enum xe_sigid sigid,
				 struct xe_ras_error_class *counter,
				 struct xe_ras_get_counter_response *response)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	struct xe_ras_get_counter_response local_resp = {};
	struct xe_ras_get_counter_response *counter_response = response;
	struct xe_cper_sec_intel_err_hdr ihdr = {};
	struct xe_cper_einfo_entry *einfo_arr = NULL;
	u32 einfo_count = 0;
	u32 i;

	if (!xe)
		return;

	if (!counter || !xe_ras_counter_is_valid(xe, counter))
		return;

	if (!counter_response) {
		counter_response = &local_resp;
		if (xe_ras_get_counter_response(xe, counter, counter_response)) {
			xe_err(xe, "[RAS]: CPER: failed to get counter, skipping record\n");
			return;
		}
	}

	if (counter_response->has_info_queue) {
		einfo_arr = xe_prepare_cper_error_info(xe, counter_response, counter, &einfo_count);
		if (!einfo_arr)
			xe_err(xe, "[RAS]: CPER: failed to build einfo from info queue\n");
	}

	if (einfo_count > 0) {
		for (i = 0; i < einfo_count; i++) {
			struct xe_cper_sec_intel_err_hdr entry_ihdr = {};

			xe_cper_init_intel_err_hdr(xe,
						   (const u8 *)&einfo_arr[i].hdr.error_class,
						   einfo_arr[i].timestamp,
						   sigid, einfo_arr[i].hdr.counter,
						   &entry_ihdr);

			xe_cper_record_emit(xe, cper_sev, &INTEL_CPER_NOTIFY_GPU_ERROR,
					    &entry_ihdr, einfo_arr[i].einfo,
					    einfo_arr[i].einfo_size);
		}
	} else {
		xe_cper_init_intel_err_hdr(xe,
					   (const u8 *)counter,
					   counter_response->timestamp,
					   sigid, counter_response->value, &ihdr);

		xe_cper_record_emit(xe, cper_sev, &INTEL_CPER_NOTIFY_GPU_ERROR,
				    &ihdr, NULL, 0);
	}

	if (einfo_arr) {
		free_einfo_arr(einfo_arr, einfo_count);
		einfo_arr = NULL;
	}

}
