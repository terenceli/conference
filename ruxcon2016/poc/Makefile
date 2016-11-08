obj-m := poc.o
KDIR  := /root/linux-xlnx-xilinx-v2015.4
PWD := $(shell pwd)
ccflags-y := -O0
default:
	make ARCH=arm CROSS_COMPILE=/root/soft/gcc-linaro-arm-linux-gnueabihf-4.9-2014.07_linux/bin/arm-linux-gnueabihf- -C $(KDIR) M=$(PWD) modules
