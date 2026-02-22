# kfetch Makefile
obj-m += kfetch_mod_111550129.o

PWD  := $(shell pwd)
# devkit
KDIR ?= $(PWD)/linux-v6.8-devkit

ARCH ?= riscv
CROSS_COMPILE ?= riscv64-linux-gnu-

all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) clean
