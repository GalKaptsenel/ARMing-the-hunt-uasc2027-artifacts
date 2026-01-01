KDIR   ?= /usr/src/linux-headers-$(shell uname -r)
CFLAGS  = -O2 -no-pie -march=armv8.3-a -Wall
LDLIBS  = -pthread

GUEST_CFLAGS = -ffreestanding -nostdlib -static -no-pie -fno-pic -mcmodel=large \
               -march=armv8.3-a -mbranch-protection=none -O2

CORE     = main.c channel.c
BOUNDARY = same.c same_btb.c xthread.c xproc.c xvm.c xel.c
HDRS     = leak.h channel.h xpv.h

obj-m := aut_xel.o

.PHONY: all clean
all: cross_boundary pac_victim guest.elf aut_xel.ko

cross_boundary: $(CORE) $(BOUNDARY) $(HDRS)
	gcc $(CFLAGS) $(CORE) $(BOUNDARY) -o $@ $(LDLIBS)

pac_victim: pac_victim.c channel.c $(HDRS)
	gcc $(CFLAGS) pac_victim.c channel.c -o $@ $(LDLIBS)

guest.elf: guest.c guest.ld
	gcc $(GUEST_CFLAGS) -Wl,-T,guest.ld guest.c -o $@

aut_xel.ko: aut_xel.c
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	rm -f cross_boundary pac_victim guest.elf
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean 2>/dev/null || true
