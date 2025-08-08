# IronVeil — Safe low-level memory tooling for Linux (5.x/6.x)
# Module: ironveil.ko

# ====== User-tweakables =======================================================
# KDIR: path to your kernel build tree
KDIR ?= /lib/modules/$(shell uname -r)/build
# Build type: set DEBUG=1 for extra checks/logging
DEBUG ?= 0
# Where to install (modprobe path = /lib/modules/$(uname -r)/<INSTALL_MOD_DIR>)
INSTALL_MOD_DIR ?= extra

# ====== Module wiring =========================================================
obj-m := ironveil.o

# Split sources (we'll add these files step-by-step)
ironveil-y := \
  src/core.o \
  src/ctl.o \
  src/vtop.o \
  src/phys.o \
  src/policy.o \
  src/crypto.o \
  src/mmap.o \
  src/netlink.o \
  src/stats.o

# Headers
ccflags-y += -I$(PWD)/include

# Warnings & hardening (keep it strict but practical for kernel)
ccflags-y += -Wall -Wextra -Werror -Wformat=2 -Wcast-align \
             -Wstrict-prototypes -Wmissing-prototypes \
             -Wno-missing-field-initializers -Wno-unused-parameter
# Kernel modules should not be PIE
ccflags-y += -fno-pie

# Optional: turn on DEBUG path
ifeq ($(DEBUG),1)
  ccflags-y += -DDEBUG -O0
else
  ccflags-y += -O2
endif

# ====== Version-aware knobs (light; main gating is done in kpm_compat.h) =====
# Try to fetch kernelrelease from the tree; fallback to uname -r
KV := $(shell $(MAKE) -sC $(KDIR) kernelrelease 2>/dev/null || uname -r)
KMAJOR := $(word 1,$(subst ., ,$(KV)))
KMINOR := $(word 2,$(subst ., ,$(KV)))

# Provide a few gentle feature flags to help conditional paths in headers
# (Most version checks happen in include/kpm_compat.h via linux/version.h)
ifeq ($(shell [ $(KMAJOR) -ge 6 ] && echo yes),yes)
  ccflags-y += -DIRONVEIL_KMAJOR_GE_6=1
else
  ccflags-y += -DIRONVEIL_KMAJOR_LT_6=1
endif

# ====== Standard Kbuild targets ==============================================
.PHONY: all modules clean clobber load unload reload install help

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -rf \
	  Module.symvers modules.order *.o *.ko *.mod *.mod.c .*.cmd \
	  *~ core .tmp_versions \
	  src/*.o src/.*.cmd src/*~ \
	  tools/c/*.o tools/c/.*.cmd tools/c/*~ \
	  tools/py/__pycache__ tests/__pycache__

clobber: clean

# ====== Convenience targets (dev workflow) ===================================
# Load with insmod; if dependencies are needed, prefer modprobe.
load: modules
	@sudo insmod ./ironveil.ko || (dmesg | tail -n 30; false)

unload:
	@sudo rmmod ironveil || (dmesg | tail -n 30; false)

reload: unload load

# Install into /lib/modules/<ver>/<INSTALL_MOD_DIR>/ironveil.ko
install: modules
	@$(MAKE) -C $(KDIR) M=$(PWD) modules_install INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)
	@sudo depmod -a
	@echo "Installed to $(INSTALL_MOD_DIR). You can 'modprobe ironveil'."

help:
	@echo "Targets:"
	@echo "  all/modules   - build the module"
	@echo "  clean/clobber - clean artifacts"
	@echo "  load/unload   - insmod/rmmod locally (dev only)"
	@echo "  reload        - rmmod then insmod"
	@echo "  install       - modules_install + depmod (use modprobe later)"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR=<path to kernel build> (default: /lib/modules/\`uname -r\`/build)"
	@echo "  DEBUG=1 to enable -DDEBUG and -O0"
	@echo "  INSTALL_MOD_DIR=<dir under /lib/modules/...> (default: extra)"
	@echo ""
	@echo "Kernel release detected: $(KV) (major=$(KMAJOR) minor=$(KMINOR))"
