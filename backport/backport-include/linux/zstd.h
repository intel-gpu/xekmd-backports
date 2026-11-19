#ifndef __BACKPORT_LINUX_ZSTD_H
#define __BACKPORT_LINUX_ZSTD_H

#include_next <linux/zstd.h>

#ifdef BPM_ZSTD_GET_PARAMS_NOT_PRESENT
typedef ZSTD_parameters zstd_parameters;
typedef ZSTD_CStream zstd_cstream;
typedef ZSTD_outBuffer zstd_out_buffer;
typedef ZSTD_inBuffer zstd_in_buffer;

#define zstd_compress_bound ZSTD_compressBound
#define zstd_compress_stream ZSTD_compressStream
#define zstd_end_stream ZSTD_endStream

static inline const char *backport_ZSTD_getErrorName(size_t result)
{
	switch (ZSTD_getErrorCode(result)) {
	case ZSTD_error_no_error:
		return "No error";
	case ZSTD_error_GENERIC:
		return "Generic error";
	case ZSTD_error_prefix_unknown:
		return "Unknown frame prefix";
	case ZSTD_error_version_unsupported:
		return "Unsupported version";
	case ZSTD_error_parameter_unknown:
		return "Unknown parameter";
	case ZSTD_error_frameParameter_unsupported:
		return "Unsupported frame parameter";
	case ZSTD_error_frameParameter_unsupportedBy32bits:
		return "Frame parameter unsupported in 32-bit mode";
	case ZSTD_error_frameParameter_windowTooLarge:
		return "Frame window too large";
	case ZSTD_error_compressionParameter_unsupported:
		return "Unsupported compression parameter";
	case ZSTD_error_init_missing:
		return "Missing initialization";
	case ZSTD_error_memory_allocation:
		return "Memory allocation failed";
	case ZSTD_error_stage_wrong:
		return "Invalid processing stage";
	case ZSTD_error_dstSize_tooSmall:
		return "Destination buffer too small";
	case ZSTD_error_srcSize_wrong:
		return "Incorrect source size";
	case ZSTD_error_corruption_detected:
		return "Corrupted data";
	case ZSTD_error_checksum_wrong:
		return "Checksum mismatch";
	case ZSTD_error_tableLog_tooLarge:
		return "Table log too large";
	case ZSTD_error_maxSymbolValue_tooLarge:
		return "Maximum symbol value too large";
	case ZSTD_error_maxSymbolValue_tooSmall:
		return "Maximum symbol value too small";
	case ZSTD_error_dictionary_corrupted:
		return "Corrupted dictionary";
	case ZSTD_error_dictionary_wrong:
		return "Incorrect dictionary";
	case ZSTD_error_dictionaryCreation_failed:
		return "Dictionary creation failed";
	default:
		return "Unknown Zstd error";
	}
}

#define ZSTD_getErrorName backport_ZSTD_getErrorName

static inline zstd_parameters zstd_get_params(int level,
					     unsigned long long estimated_src_size)
{
	return ZSTD_getParams(level, estimated_src_size, 0);
}

static inline size_t
zstd_cstream_workspace_bound(const ZSTD_compressionParameters *params)
{
	return ZSTD_CStreamWorkspaceBound(*params);
}

static inline zstd_cstream *zstd_init_cstream(const zstd_parameters *params,
					   unsigned long long pledged_src_size,
					   void *workspace, size_t workspace_size)
{
	return ZSTD_initCStream(*params, pledged_src_size, workspace, workspace_size);
}
#endif

#endif
