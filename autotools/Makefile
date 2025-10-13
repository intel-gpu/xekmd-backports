all clean xe-dkms-deb-pkg:
	$(MAKE) -C src $@

modules olddefconfig menuconfig savedefconfig:
	$(MAKE) -C src KLIB=$(LINUX_OBJ) KLIB_BUILD=$(LINUX_OBJ) $@
