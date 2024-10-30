ccflags-y += -I$(src) -Wframe-larger-than=1280
ifeq ($(CONFIG_BACKPORT_INTEGRATE),)
obj-m += compat.o
else
obj-y += compat.o
endif
compat-y += main.o

# Kernel backport compatibility code
