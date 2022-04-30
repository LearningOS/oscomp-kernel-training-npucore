PROJECT_DIR := $(shell pwd)

MUSL_TOOLCHAIN_PREFIX := riscv64-linux-musl
MUSL_TOOLCHAIN_DIR := $(PROJECT_DIR)/$(MUSL_TOOLCHAIN_PREFIX)-cross/bin
MUSL_CC := $(MUSL_TOOLCHAIN_DIR)/$(MUSL_TOOLCHAIN_PREFIX)-gcc
MUSL_AR := $(MUSL_TOOLCHAIN_DIR)/$(MUSL_TOOLCHAIN_PREFIX)-ar
MUSL_OBJCOPY := $(MUSL_TOOLCHAIN_DIR)/$(MUSL_TOOLCHAIN_PREFIX)-objcopy

BASH_DIR := bash-5.1.16
BASH := $(PROJECT_DIR)/$(BASH_DIR)/bash

$(BASH):
	cd $(BASH_DIR) \
	&& ./configure \
	--host=$(MUSL_TOOLCHAIN_PREFIX) \
	CC=$(MUSL_CC) \
	AR=$(MUSL_AR) \
	--enable-static-link \
	--without-bash-malloc \
	&& make 
	$(MUSL_OBJCOPY) --strip-debug $(BASH)

all: $(BASH)	
