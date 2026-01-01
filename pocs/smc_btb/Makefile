obj-m := smc_probe.o
KDIR ?= /usr/src/linux-headers-$(shell uname -r)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

bench: smc_bench.c
	gcc -O2 -no-pie -march=armv8.3-a smc_bench.c -o smc_bench

.PHONY: all clean bench
