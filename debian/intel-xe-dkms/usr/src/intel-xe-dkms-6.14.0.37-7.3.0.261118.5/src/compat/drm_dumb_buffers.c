#include <linux/module.h>
#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_mode_object.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_print.h>


#ifdef BPM_DRM_MODE_SIZE_DUMB_NOT_PRESENT

/**
 * drm_driver_color_mode_format - Compute DRM 4CC code from color mode
 * @dev: DRM device
 * @color_mode: command-line color mode
 *
 * Computes a DRM 4CC pixel format code for the given color mode using
 * drm_driver_color_mode(). The color mode is in the format used and the
 * kernel command line. It specifies the number of bits per pixel
 * and color depth in a single value.
 *
 * Useful in fbdev emulation code, since that deals in those values. The
 * helper does not consider YUV or other complicated formats. This means
 * only legacy formats are supported (fmt->depth is a legacy field), but
 * the framebuffer emulation can only deal with such formats, specifically
 * RGB/BGA formats.
 */
uint32_t drm_driver_color_mode_format(struct drm_device *dev, unsigned int color_mode)
{
	switch (color_mode) {
	case 15:
		return drm_driver_legacy_fb_format(dev, 16, 15);
	case 32:
		return drm_driver_legacy_fb_format(dev, 32, 24);
	default:
		return drm_driver_legacy_fb_format(dev, color_mode, color_mode);
	}
}

/**
 * To support dumb objects drivers must implement the &drm_driver.dumb_create
 * and &drm_driver.dumb_map_offset operations (the latter defaults to
 * drm_gem_dumb_map_offset() if not set). Drivers that don't use GEM handles
 * additionally need to implement the &drm_driver.dumb_destroy operation. See
 * the callbacks for further details.
 */
static int drm_mode_align_dumb(struct drm_mode_create_dumb *args,
			       unsigned long hw_pitch_align,
			       unsigned long hw_size_align)
{
	u32 pitch = args->pitch;
	u32 size;

	if (!pitch)
		return -EINVAL;

	if (hw_pitch_align)
		pitch = roundup(pitch, hw_pitch_align);

	if (!hw_size_align)
		hw_size_align = PAGE_SIZE;
	else if (!IS_ALIGNED(hw_size_align, PAGE_SIZE))
		return -EINVAL;

	if (check_mul_overflow(args->height, pitch, &size))
		return -EINVAL;
	size = ALIGN(size, hw_size_align);
	if (!size)
		return -EINVAL;

	args->pitch = pitch;
	args->size = size;

	return 0;
}

/**
 * drm_mode_size_dumb - Calculates the scanline and buffer sizes for dumb buffers
 * @dev: DRM device
 * @args: Parameters for the dumb buffer
 * @hw_pitch_align: Hardware scanline alignment in bytes
 * @hw_size_align: Hardware buffer-size alignment in bytes
 *
 * The helper drm_mode_size_dumb() calculates the size of the buffer
 * allocation and the scanline size for a dumb buffer. Callers have to
 * set the buffers width, height and color mode in the argument @arg.
 * The helper validates the correctness of the input and tests for
 * possible overflows. If successful, it returns the dumb buffer's
 * required scanline pitch and size in &args.
 *
 * The parameter @hw_pitch_align allows the driver to specifies an
 * alignment for the scanline pitch, if the hardware requires any. The
 * calculated pitch will be a multiple of the alignment. The parameter
 * @hw_size_align allows to specify an alignment for buffer sizes. The
 * provided alignment should represent requirements of the graphics
 * hardware. drm_mode_size_dumb() handles GEM-related constraints
 * automatically across all drivers and hardware. For example, the
 * returned buffer size is always a multiple of PAGE_SIZE, which is
 * required by mmap().
 *
 * Returns:
 * Zero on success, or a negative error code otherwise.
 */
int drm_mode_size_dumb(struct drm_device *dev,
		       struct drm_mode_create_dumb *args,
		       unsigned long hw_pitch_align,
		       unsigned long hw_size_align)
{
	u64 pitch = 0;
	u32 fourcc;

	fourcc = drm_driver_color_mode_format(dev, args->bpp);
	if (fourcc != DRM_FORMAT_INVALID) {
		const struct drm_format_info *info = drm_format_info(fourcc);

		if (!info)
			return -EINVAL;
		pitch = drm_format_info_min_pitch(info, 0, args->width);
	} else if (args->bpp) {
		switch (args->bpp) {
		default:
			drm_warn_once(dev,
				      "Unknown color mode %u; guessing buffer size.\n",
				      args->bpp);
			fallthrough;
		case 12: // DRM_FORMAT_YUV420_8BIT
		case 15: // DRM_FORMAT_YUV420_10BIT
		case 30: // DRM_FORMAT_VUY101010
			fallthrough;
		case 10: // DRM_FORMAT_NV{15,20,30}, DRM_FORMAT_P010
		case 64: // DRM_FORMAT_{XRGB,XBGR,ARGB,ABGR}16161616F
			pitch = args->width * DIV_ROUND_UP(args->bpp, 8);
			break;
		}
	}

	if (!pitch || pitch > U32_MAX)
		return -EINVAL;

	args->pitch = pitch;

	return drm_mode_align_dumb(args, hw_pitch_align, hw_size_align);
}
EXPORT_SYMBOL(drm_mode_size_dumb);

#endif /* BPM_DRM_MODE_SIZE_DUMB_NOT_PRESENT */
