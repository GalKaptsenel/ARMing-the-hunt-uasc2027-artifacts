# Shared prerequisite kernel modules, used across the whole tree:
#   raw_pmu.ko   grants EL0 read of the PMU counters (the EL0 PoCs' read-out helper)
#   dssbs_ctl.ko (optional) forces the Spectre-v4 window system-wide (SCTLR_EL1.DSSBS +
#                live PSTATE.SSBS); the EL0 v4 window is already open by default, so load
#                this only to force SSB across the whole system.
#
# This box has no /lib/modules/<rel>/build symlink, so point KDIR at the headers package.
#   make            build both modules
#   make load       insmod raw_pmu (root); make load-dssbs also inserts the optional dssbs_ctl
#   make unload     remove both; make clean

KDIR ?= /usr/src/linux-headers-$(shell uname -r)

obj-m := raw_pmu.o dssbs_ctl.o

.PHONY: all load load-dssbs unload clean
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

load: all
	sudo insmod raw_pmu.ko

load-dssbs: load
	sudo insmod dssbs_ctl.ko

unload:
	-sudo rmmod dssbs_ctl
	-sudo rmmod raw_pmu

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
