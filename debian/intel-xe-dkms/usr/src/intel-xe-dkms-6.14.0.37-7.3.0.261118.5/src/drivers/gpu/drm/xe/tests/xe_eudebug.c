// SPDX-License-Identifier: GPL-2.0 AND MIT
/*
 * Copyright © 2024 Intel Corporation
 */

#include <kunit/visibility.h>

#include "tests/xe_kunit_helpers.h"
#include "tests/xe_pci_test.h"
#include "tests/xe_test.h"

#undef XE_REG_MCR
#define XE_REG_MCR(r_, ...)	((const struct xe_reg_mcr){					\
				 .__reg = XE_REG_INITIALIZER(r_,  ##__VA_ARGS__, .mcr = 1)	\
				 })

static const char *reg_to_str(struct xe_reg reg)
{
	if (reg.raw == TD_CTL.__reg.raw)
		return "TD_CTL";
	else if (reg.raw == CS_DEBUG_MODE2(RENDER_RING_BASE).raw)
		return "CS_DEBUG_MODE2";
	else if (reg.raw == ROW_CHICKEN.__reg.raw)
		return "ROW_CHICKEN";
	else if (reg.raw == ROW_CHICKEN2.__reg.raw)
		return "ROW_CHICKEN2";
	else if (reg.raw == ROW_CHICKEN3.__reg.raw)
		return "ROW_CHICKEN3";
	else
		return "UNKNOWN REG";
}

static u32 get_reg_mask(struct xe_device *xe, struct xe_reg reg)
{
	struct kunit *test = kunit_get_current_test();
	u32 val = 0;

	if (reg.raw == TD_CTL.__reg.raw) {
		val = TD_CTL_BREAKPOINT_ENABLE |
		      TD_CTL_FORCE_THREAD_BREAKPOINT_ENABLE |
		      TD_CTL_FEH_AND_FEE_ENABLE;

		if (GRAPHICS_VERx100(xe) >= 1250)
			val |= TD_CTL_GLOBAL_DEBUG_ENABLE;

	} else if (reg.raw == CS_DEBUG_MODE2(RENDER_RING_BASE).raw) {
		val = GLOBAL_DEBUG_ENABLE;
	} else if (reg.raw == ROW_CHICKEN.__reg.raw) {
		val = STALL_DOP_GATING_DISABLE;
	} else if (reg.raw == ROW_CHICKEN2.__reg.raw) {
		val = XEHPC_DISABLE_BTB;
	} else if (reg.raw == ROW_CHICKEN3.__reg.raw) {
		val = XE2_EUPEND_CHK_FLUSH_DIS;
	} else {
		kunit_warn(test, "Invalid register selection: %u\n", reg.raw);
	}

	return val;
}

static u32 get_reg_expected(struct xe_device *xe, struct xe_reg reg, bool enable_eudebug)
{
	u32 reg_mask = get_reg_mask(xe, reg);
	u32 reg_bits = 0;

	if (enable_eudebug || reg.raw == ROW_CHICKEN3.__reg.raw)
		reg_bits = reg_mask;
	else
		reg_bits = 0;

	return reg_bits;
}

static void check_reg(struct xe_gt *gt, bool enable_eudebug, struct xe_reg reg)
{
	struct kunit *test = kunit_get_current_test();
	struct xe_device *xe = gt_to_xe(gt);
	u32 reg_bits_expected = get_reg_expected(xe, reg, enable_eudebug);
	u32 reg_mask = get_reg_mask(xe, reg);
	u32 reg_bits = 0;

	if (reg.mcr)
		reg_bits = xe_gt_mcr_unicast_read_any(gt, (struct xe_reg_mcr){.__reg = reg});
	else
		reg_bits = xe_mmio_read32(&gt->mmio, reg);

	reg_bits &= reg_mask;

	kunit_printk(KERN_DEBUG, test, "%s bits: expected == 0x%x; actual == 0x%x\n",
		     reg_to_str(reg), reg_bits_expected, reg_bits);
	KUNIT_EXPECT_EQ_MSG(test, reg_bits_expected, reg_bits,
			    "Invalid bits set for %s\n", reg_to_str(reg));
}

static void __check_regs(struct xe_gt *gt, bool enable_eudebug)
{
	struct xe_device *xe = gt_to_xe(gt);

	if (GRAPHICS_VERx100(xe) >= 1200)
		check_reg(gt, enable_eudebug, TD_CTL.__reg);

	if (GRAPHICS_VERx100(xe) >= 1250 && GRAPHICS_VERx100(xe) <= 1274)
		check_reg(gt, enable_eudebug, ROW_CHICKEN.__reg);

	if (xe->info.platform == XE_PVC)
		check_reg(gt, enable_eudebug, ROW_CHICKEN2.__reg);

	if (GRAPHICS_VERx100(xe) >= 2000 && GRAPHICS_VERx100(xe) <= 2004)
		check_reg(gt, enable_eudebug, ROW_CHICKEN3.__reg);
}

static void check_regs(struct xe_device *xe, bool enable_eudebug)
{
	struct kunit *test = kunit_get_current_test();
	struct xe_gt *gt;
	unsigned int fw_ref;
	u8 id;

	kunit_printk(KERN_DEBUG, test, "Check regs for eudebug %s\n",
		     enable_eudebug ? "enabled" : "disabled");

	xe_pm_runtime_get(xe);
	for_each_gt(gt, xe, id) {
		if (xe_gt_is_media_type(gt))
			continue;

		/* XXX: Figure out per platform proper domain */
		fw_ref = xe_force_wake_get(gt_to_fw(gt), XE_FORCEWAKE_ALL);
		KUNIT_ASSERT_TRUE_MSG(test, fw_ref, "Forcewake failed.\n");

		__check_regs(gt, enable_eudebug);

		xe_force_wake_put(gt_to_fw(gt), fw_ref);
	}
	xe_pm_runtime_put(xe);
}

static int toggle_reg_value(struct xe_device *xe)
{
	struct kunit *test = kunit_get_current_test();
	bool enable_eudebug = xe->eudebug.state == XE_EUDEBUG_ENABLED;

	if (IS_SRIOV_VF(xe))
		kunit_skip(test, "eudebug not available in SR-IOV VF mode\n");

	if (xe->eudebug.state == XE_EUDEBUG_NOT_SUPPORTED)
		kunit_skip(test, "eudebug not supported\n");

	kunit_printk(KERN_DEBUG, test, "Test eudebug WAs for graphics version: %u\n",
		     GRAPHICS_VERx100(xe));

	check_regs(xe, enable_eudebug);

	xe_eudebug_enable(xe, !enable_eudebug);
	check_regs(xe, !enable_eudebug);

	xe_eudebug_enable(xe, enable_eudebug);
	check_regs(xe, enable_eudebug);

	return 0;
}

static void xe_eudebug_toggle_reg_kunit(struct kunit *test)
{
	struct xe_device *xe = test->priv;

	toggle_reg_value(xe);
}

static struct kunit_case xe_eudebug_tests[] = {
	KUNIT_CASE_PARAM(xe_eudebug_toggle_reg_kunit,
			 xe_pci_live_device_gen_param),
	{}
};

VISIBLE_IF_KUNIT
struct kunit_suite xe_eudebug_test_suite = {
	.name = "xe_eudebug",
	.test_cases = xe_eudebug_tests,
	.init = xe_kunit_helper_xe_device_live_test_init,
};
EXPORT_SYMBOL_IF_KUNIT(xe_eudebug_test_suite);
