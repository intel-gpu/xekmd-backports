# SPDX-License-Identifier: GPL-2.0
#
# Makefile for drivers/platform/x86/intel
# Intel x86 Platform-Specific Drivers
#
#
#obj-$(CONFIG_INTEL_ATOMISP2_PDX86)	+= atomisp2/
#obj-$(CONFIG_INTEL_IFS)			+= ifs/
#obj-$(CONFIG_INTEL_SAR_INT1092)		+= int1092/
#obj-$(CONFIG_INTEL_SKL_INT3472)		+= int3472/
#obj-$(CONFIG_INTEL_PMC_CORE)		+= pmc/
obj-$(CONFIG_INTEL_PMT_CLASS)		+= pmt/
#obj-$(CONFIG_INTEL_SPEED_SELECT_INTERFACE) += speed_select_if/
#obj-$(CONFIG_INTEL_TELEMETRY)		+= telemetry/
#obj-$(CONFIG_INTEL_WMI)			+= wmi/
#obj-$(CONFIG_INTEL_UNCORE_FREQ_CONTROL)	+= uncore-frequency/

intel-target-$(CONFIG_INTEL_VSEC)		+= vsec.o

# Add 'intel' prefix to each module listed in intel-target-*
define INTEL_OBJ_TARGET
intel-$(1)-y := $(1).o
obj-$(2) += intel-$(1).o
endef

$(foreach target, $(basename $(intel-target-y)), $(eval $(call INTEL_OBJ_TARGET,$(target),y)))
$(foreach target, $(basename $(intel-target-m)), $(eval $(call INTEL_OBJ_TARGET,$(target),m)))
