# Check if being called by kernel build system
ifneq ($(KERNELRELEASE),)
# Called by kernel build system - descend into src/
obj-y := src/
else
# User/packaging mode

# Version extraction from backport versions file
BKPT_VER=$(shell cat src/versions | grep BACKPORTS_RELEASE_TAG | cut -d '"' -f 2 | cut -d '_' -f 3 2>/dev/null || echo 1)
BP_TAG=$(shell cat src/versions | grep BACKPORTS_RELEASE_TAG | cut -d '"' -f 2 | cut -d '_' -f 2 2>/dev/null || echo 1)
BP_DATE=$(shell echo $(BKPT_VER) | cut -d "." -f 1 2>/dev/null || echo 1)

# Get kernel version - from KLIB/KLIB_BUILD headers if provided, else from uname -r
ifneq ($(origin KLIB), undefined)
  KLIB_BUILD ?= $(KLIB)/build/
  TARGET_KERN_VER=$(shell cat $(KLIB_BUILD)/include/generated/autoconf.h 2>/dev/null | grep 'CONFIG_BUILD_SALT' | cut -d '"' -f2 2>/dev/null || cat $(KLIB_BUILD)/include/generated/utsrelease.h 2>/dev/null | grep "UTS_RELEASE" | cut -d '"' -f2 2>/dev/null || uname -r)
else ifneq ($(origin KLIB_BUILD), undefined)
  KLIB ?= $(patsubst %/build,%,$(KLIB_BUILD))
  TARGET_KERN_VER=$(shell cat $(KLIB_BUILD)/include/generated/autoconf.h 2>/dev/null | grep 'CONFIG_BUILD_SALT' | cut -d '"' -f2 2>/dev/null || cat $(KLIB_BUILD)/include/generated/utsrelease.h 2>/dev/null | grep "UTS_RELEASE" | cut -d '"' -f2 2>/dev/null || uname -r)
else
  KLIB := /lib/modules/$(shell uname -r)/
  KLIB_BUILD ?= $(KLIB)/build/
  TARGET_KERN_VER=$(shell uname -r)
endif

BACKPORT_DIR = src
CONFIG_SHELL = /bin/bash

# Extract kernel version components
FULL_KERN_STR=$(shell echo "$(TARGET_KERN_VER)" | sed 's/\.el[0-9]*_[0-9]*\.x86_64//' | sed 's/\.x86_64//' | tr -d '+')
KER_VER=$(subst -,.,$(FULL_KERN_STR))
DISTRO_SUFFIX=$(shell echo "$(TARGET_KERN_VER)" | grep -o 'el[0-9]*_[0-9]*' | head -1)

# Package version format: kernel_version.bp_tag.date
VERSION=$(KER_VER).$(BP_TAG).$(BP_DATE)

XE_PKG_NAME=intel-xe-dkms
XE_PKG_VERSION=$(VERSION)
XE_PKG_RELEASE=1
XE_RPM_MK_SPEC=$(BACKPORT_DIR)/scripts/backport-mkrpmcontrol
XE_RPM_MK_DKMS=$(BACKPORT_DIR)/scripts/backport-mkxerpmdkms

# Export variables for sub-makes
export KLIB KLIB_BUILD

.PHONY: all clean xe-dkms-deb-pkg
all clean xe-dkms-deb-pkg:
	$(MAKE) -C src $@

.PHONY: modules olddefconfig menuconfig savedefconfig
modules olddefconfig menuconfig savedefconfig:
	$(MAKE) -C src KLIB=$(KLIB) KLIB_BUILD=$(KLIB_BUILD) $@

.PHONY: show-version
show-version:
	@echo "Target Kernel Version : $(TARGET_KERN_VER)"
	@echo "Kernel Headers Path   : $(KLIB_BUILD)"
	@echo "Package Version       : $(XE_PKG_VERSION)"
	@echo "Package Release       : $(XE_PKG_RELEASE)$(if $(DISTRO_SUFFIX),.$(DISTRO_SUFFIX))"
	@echo "Expected RPM Name     : $(XE_PKG_NAME)-$(XE_PKG_VERSION)-$(XE_PKG_RELEASE)$(if $(DISTRO_SUFFIX),.$(DISTRO_SUFFIX)).x86_64.rpm"

.PHONY: xe-dkms-rpm-pkg
xe-dkms-rpm-pkg: clean
	@echo "========================================"
	@echo "Building DKMS RPM package"
	@echo "Target Kernel: $(TARGET_KERN_VER)"
	@echo "Package version: $(XE_PKG_VERSION)-$(XE_PKG_RELEASE)"
	@echo "========================================"
	@echo "Pre-configuring source for DKMS..."
	@cd src && test -f .config || $(MAKE) defconfig-xe
	@echo "Pre-generating backport autoconf.h..."
	@cd src && $(MAKE) backport-include/backport/autoconf.h
	mkdir -p rpm
	mkdir -p ~/rpmbuild/SOURCES
	$(CONFIG_SHELL) $(XE_RPM_MK_SPEC) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) $(if $(DISTRO_SUFFIX),-d $(DISTRO_SUFFIX)) -z dkms > rpm/$(XE_PKG_NAME).spec
	$(CONFIG_SHELL) $(XE_RPM_MK_DKMS) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r 1 > rpm/$(XE_PKG_NAME).dkms.conf
	cp -r src m4 debian Makefile* configure* aclocal.m4 AUTHORS ChangeLog COPYING INSTALL NEWS README compile.sh ~/rpmbuild/SOURCES/ 2>/dev/null || true
	+rpmbuild -bb --define "_sourcedir $(PWD)" rpm/$(XE_PKG_NAME).spec

endif # End of user/packaging mode
