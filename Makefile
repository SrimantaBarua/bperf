obj-m      += bperf.o
bperf-objs += src/bperf.o src/arch_defs.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

