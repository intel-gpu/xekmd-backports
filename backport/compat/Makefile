ccflags-y += -I$(src) -Wframe-larger-than=1280
ifeq ($(CONFIG_BACKPORT_INTEGRATE),)
obj-m += xe-compat.o
else
obj-y += xe-compat.o
endif

xe-compat-y += main.o ptrace.o iov.o drm_drv.o drm_managed.o hrtimer.o memory.o dma-fence-array.o drm_print.o drm_dumb_buffers.o
xe-compat-y += anon_inodes.o iommu.o

ifeq ($(CPTCFG_DRM_GPUVM),)
xe-compat-y += drm_gpuvm.o drm_gpuvm_madvise.o
endif

# Kernel backport compatibility code
