MUSL_TOOLCHAIN_PREFIX := riscv64-linux-musl
MUSL_CC := $(MUSL_TOOLCHAIN_PREFIX)-gcc
MUSL_AR := $(MUSL_TOOLCHAIN_PREFIX)-ar
MUSL_OBJCOPY := $(MUSL_TOOLCHAIN_PREFIX)-objcopy

BASH_DIR := bash-5.1.16
BASH := $(BASH_DIR)/bash

$(BASH):
	$(BASH_DIR)/configure \
	--host=$(MUSL_TOOLCHAIN_PREFIX) \
	CC=$(MUSL_CC) \
	AR=$(MUSL_AR) \
	--enable-static-link \
	--without-bash-malloc
	$(MAKE) -C $(BASH_DIR)
	$(MUSL_OBJCOPY) --strip-debug $(BASH)

all: $(BASH)	
