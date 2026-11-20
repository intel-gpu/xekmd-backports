KLIB ?= /lib/modules/$(shell uname -r)
KLIB_BUILD ?= $(KLIB)/build

all clean:
	$(MAKE) -C src $@

modules olddefconfig menuconfig savedefconfig:
	$(MAKE) -C src KLIB=$(KLIB) KLIB_BUILD=$(KLIB_BUILD) $@

.PHONY: xe-dkms-deb-pkg xe-dkms-rpm-pkg
xe-dkms-deb-pkg xe-dkms-rpm-pkg:
	./oot-build.sh configure "$(KLIB_BUILD)"
	$(MAKE) $@-build
