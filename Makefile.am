#
# Backports Makefile
#

#------------------------------------------------------------------------------
#
# GLOBAL VARIABLES
#
##------------------------------------------------------------------------------

#
# KERNEL VARIABLES
#

#
# BACKPORT VARIABLES
#

#
# OSV GENERIC VARIABLES
#

# Kernel build directory - defaults to running kernel
KLIB_BUILD ?= /lib/modules/@DOLLAR_SIGN@(shell uname -r)/build

RELEASE=1

# BKPT_VER consist of backported release version.
# Expected input: 'BACKPORTS_RELEASE_TAG="xeb_v6.17.13.43_260317.0"'
# Filtered output: 260317.0
BKPT_VER=@DOLLAR_SIGN@(shell cat src/versions | grep BACKPORTS_RELEASE_TAG | cut -d "_" -f 5 | cut -d "\"" -f 1 | cut -d "-" -f 1 2>/dev/null || echo 1)

# BP_TAG is the backport tag from versions file  
# Expected input: 'BACKPORTS_RELEASE_TAG="xeb_v6.17.13.43_260317.0"'
# Filtered output: v6.17.13.43
BP_TAG=@DOLLAR_SIGN@(shell cat src/versions | grep BACKPORTS_RELEASE_TAG | cut -d "_" -f 2-4 | sed 's/_/-/g' 2>/dev/null || echo 1)

# Extract date portion from BKPT_VER (first 6 digits before any dot)
# Expected input: 260317.0
# Filtered output: 260317
BP_DATE=@DOLLAR_SIGN@(shell echo $(BKPT_VER) | cut -d "." -f 1 2>/dev/null || echo 1)

# DEV_TAG is extracted from BASE_KERNEL_TAG, which is auto genereated from Dev kernel source.
# Tagging is needed for decoding
DEV_TAG=@DOLLAR_SIGN@(shell cat src/versions | grep BASE_KERNEL_TAG | cut -f 2 -d "\"" | cut -d "-" -f 3 2>/dev/null || echo 1)

# Extract kernel version from build system
UTS_RELEASE=@DOLLAR_SIGN@(shell cat $(KLIB_BUILD)/include/generated/utsrelease.h 2>/dev/null | grep "UTS_RELEASE" | cut -d "\"" -f 2 | tr -d '~+')

# Base kernel version (X.Y.Z)
KERN_VER_XYZ=@DOLLAR_SIGN@(shell cat $(KLIB_BUILD)/include/generated/utsrelease.h 2>/dev/null | grep "UTS_RELEASE" | cut -d '"' -f2 | cut -d '.' -f1-3 | cut -d '-' -f1 | tr -d '+')

# Extract extended version for RHEL/similar (e.g., 124.49.1 from 6.12.0-124.49.1.el10_1.x86_64)
EXTENDED_VERSION_STR=@DOLLAR_SIGN@(shell cat $(KLIB_BUILD)/include/generated/utsrelease.h 2>/dev/null | grep UTS_RELEASE | cut -d '"' -f2 | cut -d '-' -f2 | sed 's/\.el.*//' | sed 's/\.x86_64//')

# Construct full kernel version: X.Y.Z-EXT.VER.STR
BASE_KERNEL_NAME=@DOLLAR_SIGN@(shell test -n "$(EXTENDED_VERSION_STR)" && echo "$(KERN_VER_XYZ)-$(EXTENDED_VERSION_STR)" || echo "$(KERN_VER_XYZ)")

# Kernel version with dots instead of hyphens  
KER_VER=@DOLLAR_SIGN@(subst -,.,$(BASE_KERNEL_NAME))

# Distro suffix (e.g., el10_1)
DISTRO_SUFFIX=@DOLLAR_SIGN@(shell cat $(KLIB_BUILD)/include/generated/utsrelease.h 2>/dev/null | grep UTS_RELEASE | cut -d '"' -f2 | grep -o 'el[0-9]*_[0-9]*' | head -1)

# Package version format: kernel_version-bp_tag-date
VERSION=$(KER_VER)-$(BP_TAG)-$(BP_DATE)

#------------------------------------------------------------------------------
#
# DKMS Package Targets
#
#------------------------------------------------------------------------------

XE_PKG_NAME_BASENAME=intel-xe-dkms
XE_PKG_NAME=$(XE_PKG_NAME_BASENAME)
XE_PKG_VERSION=$(VERSION)
XE_PKG_RELEASE=$(RELEASE)

#------------------------------------------------------------------------------
#
# Debian Package Targets
#
#------------------------------------------------------------------------------
BACKPORT_DIR = src

#read default version from changelog.in and replace it with proper version info during package generation
DEF_VER=@DOLLAR_SIGN@(shell cat debian/changelog.in | head -1 | cut -d '(' -f 2 | cut -d ')' -f 1)

#------------------------------------------------------------------------------
# Debian DKMS Package Targets
#------------------------------------------------------------------------------

# xe-dkms-deb-pkggg
# Creates Backports xe alone DKMS debian package
#------------------------------------------------------------------------------


export KBUILD_ONLYXEDIRS := src/drivers/gpu src/include src/scripts src/drivers/platform src/drivers/mtd
export KBUILD_XEVFIOPCIDIRS := src/drivers/vfio/pci/xe
export KBUILD_AUTOTOOLS := m4 AUTHORS  ChangeLog  configure.ac  COPYING  INSTALL Makefile  Makefile.am  NEWS  README.md compile.sh
XE_TAR_CONTENT=$(KBUILD_ONLYXEDIRS) $(KBUILD_AUTOTOOLS) $(KBUILD_XEVFIOPCIDIRS) src/Makefile* src/local-symbols src/MAINTAINERS src/local-symbols-autoconf \
	src/Kconfig src/Kconfig.sources src/Kconfig.package.hacks src/COPYING src/versions src/defconfigs src/backport-include src/kconf src/compat

XE_DKMS_MK_CONTROL=$(BACKPORT_DIR)/scripts/backport-mkdebcontrol
XE_DKMS_MK_RULES=$(BACKPORT_DIR)/scripts/backport-mkdebrules
XE_DKMS_MK_DKMS=$(BACKPORT_DIR)/scripts/backport-mkxedebdkms
XE_DKMS_MK_README=$(BACKPORT_DIR)/scripts/backport-mkdebreadme
XE_DKMS_MK_COPYRIGHT=$(BACKPORT_DIR)/scripts/backport-mkdebcopyright

#------------------------------------------------------------------------------
#
# RPM Package Targets
#
#------------------------------------------------------------------------------

XE_RPM_MK_SPEC=$(BACKPORT_DIR)/scripts/backport-mkrpmcontrol
XE_RPM_MK_DKMS=$(BACKPORT_DIR)/scripts/backport-mkxerpmdkms

.PHONY: xe-dkms-deb-pkg
xe-dkms-deb-pkg: clean
	$(CONFIG_SHELL) $(XE_DKMS_MK_CONTROL) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) -z dkms > debian/control
	$(CONFIG_SHELL) $(XE_DKMS_MK_RULES) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) -z dkms > debian/rules
	cp debian/changelog.in debian/changelog
	sed -i 's/pkg-name/$(XE_PKG_NAME)/g' debian/changelog
	sed -i 's/$(DEF_VER)/$(XE_PKG_VERSION)/g' debian/changelog
	for i in $(XE_TAR_CONTENT); do  	\
		z=$$(expr index $$i "=")	;\
		if [ $$z = 0 ]; then		\
			x=$$(expr index $$i "/");\
			if [ $$x != 0 ]; then	\
				y=`dirname $$i`	;\
				echo "$$i /usr/src/@BACKPORT_PACKAGE_NAME@-@BACKPORT_PACKAGE_VERSION@/$$y";\
			else 	\
				echo "$$i /usr/src/@BACKPORT_PACKAGE_NAME@-@BACKPORT_PACKAGE_VERSION@";\
			fi		\
		fi 		\
	done > debian/$(XE_PKG_NAME).install.in
	$(CONFIG_SHELL) $(XE_DKMS_MK_DKMS) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) > debian/$(XE_PKG_NAME).dkms.in
	$(CONFIG_SHELL) $(XE_DKMS_MK_README) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) > debian/README.Debian
	$(CONFIG_SHELL) $(XE_DKMS_MK_COPYRIGHT) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) > debian/copyright
	+dch -l "+i${XE_PKG_RELEASE}-" -m "build ${XE_PKG_RELEASE}"
	+dpkg-buildpackage -j`nproc --all` -us -uc -b -rfakeroot

.PHONY: xe-dkms-rpm-pkg
xe-dkms-rpm-pkg: clean
	mkdir -p rpm
	mkdir -p ~/rpmbuild/SOURCES
	$(CONFIG_SHELL) $(XE_RPM_MK_SPEC) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) -d $(DISTRO_SUFFIX) -z dkms > rpm/$(XE_PKG_NAME).spec
	$(CONFIG_SHELL) $(XE_RPM_MK_DKMS) -n $(XE_PKG_NAME) -v $(XE_PKG_VERSION) -r $(XE_PKG_RELEASE) > rpm/$(XE_PKG_NAME).dkms.conf
	cp -r src m4 debian Makefile* configure* aclocal.m4 AUTHORS ChangeLog COPYING INSTALL NEWS README compile.sh ~/rpmbuild/SOURCES/ 2>/dev/null || true
	+rpmbuild -bb --define "_sourcedir $(PWD)" rpm/$(XE_PKG_NAME).spec

all clean:
	$(MAKE) -C src $@

olddefconfig menuconfig savedefconfig:
	$(MAKE) -C src KLIB=$(LINUX_OBJ) KLIB_BUILD=$(LINUX_OBJ) $@


.PHONY: modules
modules: clean
	$(shell ./src/scripts/create_automacro_h.sh -h $(LINUX_OBJ) -b $(BACKPORT_DIR))
	$(MAKE) -C src KLIB=$(LINUX_OBJ) KLIB_BUILD=$(LINUX_OBJ) $@

#------------------------------------------------------------------------------
#
# Make Targets
#
# Add all make targets for generative, packaging, build Targets.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
#
# Make build clean Targets
#
#------------------------------------------------------------------------------

# Make Mr proper to clean-up all generated files.
# Versions file will not be cleaned-up to maintain built kernel versions.
#------------------------------------------------------------------------------
.PHONY: mrproper
mrproper:
	@rm -f debian/README.Debian
	@rm -f debian/changelog
	@rm -f debian/control
	@rm -f debian/copyright
	@rm -f debian/$(XE_PKG_NAME_BASENAME)*.dkms.in
	@rm -f debian/$(XE_PKG_NAME_BASENAME)*.install.in
	@rm -rf debian/$(XE_PKG_NAME_BASENAME)*
	@rm -f debian/rules
	@rm -f rpm/$(XE_PKG_NAME).spec
	@rm -f rpm/$(XE_PKG_NAME).dkms.conf
	@rm -rf rpm/
	@rm -f src/dkms.conf
	@test -f .config && $(MAKE) clean || true


PHONY = FORCE
FORCE:
