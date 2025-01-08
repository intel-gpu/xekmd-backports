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

RELEASE=1

# BKPT_VER consist of backported release version.
# Expected input: 'BACKPORTS_RELEASE_TAG="XE_586_241121.0"'
# Filtered output: 241121.0
BKPT_VER=@DOLLAR_SIGN@(shell cat src/versions | grep BACKPORTS_RELEASE_TAG | cut -d "_" -f 5 | cut -d "\"" -f 1 | cut -d "-" -f 1 2>/dev/null || echo 1)

# DEV_TAG is extracted from BASE_KERNEL_TAG, which is auto genereated from Dev kernel source.
# Tagging is needed for decoding
DEV_TAG=@DOLLAR_SIGN@(shell cat src/versions | grep BASE_KERNEL_TAG | cut -f 2 -d "\"" | cut -d "-" -f 3 2>/dev/null || echo 1)

VERSION=1.$(BKPT_VER)

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


export KBUILD_ONLYXEDIRS := src/drivers/gpu src/include src/scripts
export KBUILD_AUTOTOOLS := m4 AUTHORS  ChangeLog  configure.ac  COPYING  INSTALL Makefile  Makefile.am  NEWS  README compile.sh
XE_TAR_CONTENT=$(KBUILD_ONLYXEDIRS) $(KBUILD_AUTOTOOLS) src/Makefile* src/local-symbols src/MAINTAINERS \
	src/Kconfig src/Kconfig.sources src/Kconfig.package.hacks src/COPYING src/versions src/defconfigs src/backport-include src/kconf src/compat

XE_DKMS_MK_CONTROL=$(BACKPORT_DIR)/scripts/backport-mkdebcontrol
XE_DKMS_MK_RULES=$(BACKPORT_DIR)/scripts/backport-mkdebrules
XE_DKMS_MK_DKMS=$(BACKPORT_DIR)/scripts/backport-mkxedebdkms
XE_DKMS_MK_README=$(BACKPORT_DIR)/scripts/backport-mkdebreadme
XE_DKMS_MK_COPYRIGHT=$(BACKPORT_DIR)/scripts/backport-mkdebcopyright

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
	@rm -f src/dkms.conf
	@test -f .config && $(MAKE) clean || true


PHONY = FORCE
FORCE:
