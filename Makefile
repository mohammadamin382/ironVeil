# ============================================================================
# IronVeil — Makefile (final)
# Safe low-level memory & crypto tooling for Linux (5.x/6.x)
# Module: ironveil.ko
#
# Usage:
#   make                   # build module
#   make load              # insmod ironveil.ko
#   make unload            # rmmod ironveil
#   make reload            # unload + load
#   make install           # install into /lib/modules/... (then modprobe ironveil)
#   make tools             # build user-space C tool (kpmctl)
#   make clean             # clean build artifacts
#
# Knobs:
#   DEBUG=1     -> extra logs, -DDEBUG, -O0
#   STRICT=1    -> treat warnings as errors (-Werror)
#   CLANG=1     -> use clang instead of gcc (if your kernel tree supports it)
#   KDIR=...    -> kernel build dir (defaults to running kernel)
#   INSTALL_MOD_DIR=extra -> destination under /lib/modules/$(uname -r)
# ============================================================================

ccflags-y += -I$(PWD)/include
# ---- Kernel tree ------------------------------------------------------------
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# ---- Build knobs ------------------------------------------------------------
DEBUG  ?= 0
STRICT ?= 1
CLANG  ?= 0

INSTALL_MOD_DIR ?= extra

# ---- Module objects ---------------------------------------------------------
obj-m := ironveil.o

# Keep sources grouped for clarity.
ironveil-y := \
  src/core.o    \
  src/ctl.o     \
  src/vtop.o    \
  src/phys.o    \
  src/policy.o  \
  src/crypto.o  \
  src/stats.o   \
  src/mmap.o    \
  src/netlink.o

# ---- Include path for our headers ------------------------------------------

# ---- Warnings & hardening (practical + strict) ------------------------------
# Kernel already sets many flags; we add a careful set here.
ccflags-y += -Wall -Wextra -Wformat=2 -Wcast-align -Wundef \
             -Wmissing-declarations -Wmissing-prototypes \
             -Wshadow -Wpointer-arith -Wwrite-strings \
             -Wvla -Wstrict-prototypes \
             -Wno-missing-field-initializers -Wno-unused-parameter
# Modules should not be PIE
ccflags-y += -fno-pie

ifeq ($(STRICT),1)
  ccflags-y += -Werror
endif

# ---- Opt level / Debug ------------------------------------------------------
ifeq ($(DEBUG),1)
  ccflags-y += -DDEBUG -O0
else
  ccflags-y += -O2
endif

# ---- Compiler switch (optional) --------------------------------------------
ifeq ($(CLANG),1)
  # Many kernel trees honor LLVM=1 for full clang+lld toolchain
  # You can also pass LLVM=1 on the command line instead.
  KMAKE_LLVM := LLVM=1
endif

# ---- Light version-detection for conditional paths in headers ---------------
KV      := $(shell $(MAKE) -sC $(KDIR) kernelrelease 2>/dev/null || uname -r)
KMAJOR  := $(word 1,$(subst ., ,$(KV)))
KMINOR  := $(word 2,$(subst ., ,$(KV)))

ifeq ($(shell [ $(KMAJOR) -ge 6 ] && echo yes),yes)
  ccflags-y += -DIRONVEIL_KMAJOR_GE_6=1
else
  ccflags-y += -DIRONVEIL_KMAJOR_LT_6=1
endif

# ---- Standard kbuild phony targets -----------------------------------------
.PHONY: all modules clean clobber load unload reload install help tools

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KMAKE_LLVM) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $(KMAKE_LLVM) clean
	@rm -rf \
	  Module.symvers modules.order *.o *.ko *.mod *.mod.c .*.cmd \
	  *~ core .tmp_versions \
	  src/*.o src/.*.cmd src/*~ \
	  tools/c/*.o tools/c/.*.cmd tools/c/*~ \
	  tools/py/__pycache__ tests/__pycache__

clobber: clean

# ---- Convenience dev targets ------------------------------------------------
load: modules
	@sudo insmod ./ironveil.ko || (dmesg | tail -n 50; false)

unload:
	@sudo rmmod ironveil || (dmesg | tail -n 50; false)

reload: unload load

install: modules
	@$(MAKE) -C $(KDIR) M=$(PWD) $(KMAKE_LLVM) modules_install INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)
	@sudo depmod -a
	@echo "[IronVeil] Installed under '$(INSTALL_MOD_DIR)'. Run: sudo modprobe ironveil"

help:
	@echo "IronVeil Makefile"
	@echo "  targets: all/modules clean/clobber load/unload reload install tools help"
	@echo "  vars:    DEBUG=$(DEBUG) STRICT=$(STRICT) CLANG=$(CLANG) KDIR=$(KDIR)"
	@echo "  kernel:  detected $(KV) (major=$(KMAJOR) minor=$(KMINOR))"

# ---- Build user-space C tool (kpmctl) --------------------------------------
tools:
	@mkdir -p tools/c
	$(CC) -O2 -Wall -Wextra -o tools/c/kpmctl tools/c/kpmctl.c -Iinclude
	@echo "[IronVeil] Built tools/c/kpmctl"
