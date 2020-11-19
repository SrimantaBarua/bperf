obj-m += src/bperf.o

.PHONY: all clean bperf_kobj bperf_user

all: bperf_kobj bperf_user

bperf_kobj:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

bperf_user: bperf

bperf: src/bperf_user.c
	gcc -o $@ $^ -O2

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f bperf

