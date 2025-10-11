ccflags-y += -I$(src) -Wframe-larger-than=1280
ifeq ($(CONFIG_BACKPORT_INTEGRATE),)
obj-m += xe-compat.o
else
obj-y += xe-compat.o
endif
xe-compat-y += main.o ptrace.o iov.o drm_drv.o drm_managed.o hrtimer.o

# Kernel backport compatibility code
