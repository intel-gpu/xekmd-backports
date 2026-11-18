# SPDX-License-Identifier: GPL-2.0

subdir-ccflags-$(CPTCFG_DRM_XE_DISPLAY) += \
	-I$(backport_srctree)/drivers/gpu/drm/i915/display/

# Rule to build display code shared with i915
$(obj)/i915-display/tests/%.o: $(backport_srctree)/drivers/gpu/drm/i915/display/tests/%.c FORCE
	$(call cmd,force_checksrc)
	$(call if_changed_rule,cc_o_c)

obj-$(CPTCFG_DRM_XE_KUNIT_TEST) += xe_display_test.o
xe_display_test-y = \
		i915-display/tests/intel_dp_link_test.o
