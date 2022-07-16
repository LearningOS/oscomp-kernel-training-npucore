# Building
TARGET := riscv64gc-unknown-none-elf
MODE := release
RUSTSBI_K210_ELF := ../rustsbi-k210/target/riscv64imac-unknown-none-elf/debug/rustsbi-k210
RUSTSBI_K210_BIN := $(RUSTSBI_K210_ELF).bin
RUSTSBI_MISAL_ELF := ../rustsbi-k210/target/riscv64gc-unknown-none-elf/release/rustsbi-k210
KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := $(KERNEL_ELF).bin
DISASM_TMP := target/$(TARGET)/$(MODE)/asm
FS_IMG := ../user/target/$(TARGET)/$(MODE)/fs.img
U_FAT32_DIR := ../easy-fs-fuse
CORE_NUM := 1
ifeq ($(BOARD), k210)
	U_FAT32 := /dev/sdc
else 
	U_FAT32 := ${U_FAT32_DIR}/fat32.img
endif


SDDEV := $(shell lsblk -do NAME | grep sd | tail -1)
SDCARD := /dev/$(SDDEV)
APPS := ../user/src/bin/*
TOP := ../../k210.bin

# BOARD
BOARD ?= qemu
SBI ?= opensbi-1.0
ifeq ($(BOARD), qemu)
	ifeq ($(SBI), rustsbi)
		BOOTLOADER := ../bootloader/$(SBI)-$(BOARD).bin
	else ifeq ($(SBI), default)
		BOOTLOADER := default
	else
		BOOTLOADER := ../bootloader/fw_payload.bin
	endif
else ifeq ($(BOARD), k210)
#	BOOTLOADER := ../bootloader/rustsbi-$(BOARD).bin
	BOOTLOADER := ../bootloader/rustsbi-misal.bin
endif
K210_BOOTLOADER_SIZE := 131072

# KERNEL ENTRY
ifeq ($(BOARD), qemu)
	KERNEL_ENTRY_PA := 0x80200000
else ifeq ($(BOARD), k210)
	KERNEL_ENTRY_PA := 0x80020000
endif

# Run K210
K210-SERIALPORT-LINUX = /dev/ttyUSB0
K210-SERIALPORT-WINDOWS = COM11
K210-BURNER = ../tools/kflash.py

# Binutils
OBJDUMP := rust-objdump --arch-name=riscv64
OBJCOPY := rust-objcopy --binary-architecture=riscv64

# Disassembly
DISASM ?= -x
# build: env $(KERNEL_BIN) $(FS_IMG) fat32
build: env $(KERNEL_BIN)

env:
	(rustup target list | grep "riscv64gc-unknown-none-elf (installed)") || rustup target add $(TARGET)
#	cargo install cargo-binutils --vers ~0.2
	rustup component add rust-src
	rustup component add llvm-tools-preview

# build all user programs
user:
	@cd ../user && make
c-user:
	@cd ../user && make c-user
rust-user:
	@cd ../user && make rust-user
# dev/zero永远输出0
sdcard:
    ifeq ($(findstring WSL, $(shell uname -a)), )
		@echo "Are you sure write to $(SDCARD) ? \nYou may also specify another drive with the option \`SDCARD=/dev/<drive>\` [y/N] " && read ans && [ $${ans:-N} = y ]
		./buildfs.sh "$(SDCARD)"
    else
		@echo "Are you sure write to E:/ ? [y/N] " && read ans && [ $${ans:-N} = y ]
		@sudo mount ../fat32-fuse/fat32.img ../fat32-fuse/fs
		@powershell.exe 'cd ../fat32-fuse; copy -Recurse -path "$$(pwd)/fs/*" -destination "E:/" -force'
		@sudo umount ../fat32-fuse/fs
    endif

$(KERNEL_BIN): kernel
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $@
#	@$(OBJDUMP) -S $(KERNEL_ELF) > $(KERNEL_ELF).S

$(APPS):

fat32:
	./buildfs.sh "$(U_FAT32_DIR)/fat32.img"

fsimg-format:
	sudo mkfs.vfat -F 32 ${U_FAT32}

bootloader:
	@cd ../rustsbi-k210 && cargo build
	@$(OBJCOPY) $(RUSTSBI_K210_ELF) --strip-all -O binary ../bootloader/rustsbi-k210.bin
	@$(OBJDUMP) -S $(RUSTSBI_K210_ELF) > ../bootloader/rustsbi-k210.S
try_bootldr:
	@cd ../rustsbi-k210 && cargo build
	@$(OBJCOPY) $(RUSTSBI_MISAL_ELF) --strip-all -O binary ../bootloader/rustsbi-misal.bin
	@$(OBJDUMP) -S $(RUSTSBI_MISAL_ELF) > ../bootloader/rustsbi-misal.S
kernel:
	@echo Platform: $(BOARD)
	@cp src/linker-$(BOARD).ld src/linker.ld
    ifeq ($(MODE), debug)
		@cargo build --features "board_$(BOARD)"
    else
		@cargo build --release --features "board_$(BOARD)"
    endif
		@rm src/linker.ld

clean:
	@cargo clean

run: run-inner

run-inner: build do-run

do-run:
ifeq ($(BOARD), qemu)
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) \
		-drive file=$(U_FAT32),if=none,format=raw,id=x0 \
        -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
		-smp threads=$(CORE_NUM)
else
	if [ ! -e "$(K210-BURNER)" ]; then (cd .. && git clone https://gitee.com/begehau/kflash.py.git && mv kflash.py tools) fi
	@cp $(BOOTLOADER) $(BOOTLOADER).copy
	@dd if=$(KERNEL_BIN) of=$(BOOTLOADER).copy bs=$(K210_BOOTLOADER_SIZE) seek=1
	@mv $(BOOTLOADER).copy $(KERNEL_BIN)
    ifeq ($(findstring WSL, $(shell uname -a)), )
		@sudo chmod 777 $(K210-SERIALPORT-LINUX)
		python3 $(K210-BURNER) -p $(K210-SERIALPORT-LINUX) -b 1500000 $(KERNEL_BIN)
		python3 -m serial.tools.miniterm --eol LF --dtr 0 --rts 0 --filter direct $(K210-SERIALPORT-LINUX) 115200
    else
		powershell.exe 'usbipd wsl detach --all; python $(K210-BURNER) -p $(K210-SERIALPORT-WINDOWS) -b 1500000 $(KERNEL_BIN); (usbipd wsl list | findstr "$(K210-SERIALPORT-WINDOWS)") -match "\d-\d"; usbipd wsl attach --busid $$matches[0]'
		@sleep 1
		@sudo chmod 777 $(K210-SERIALPORT-LINUX)
		python3 -m serial.tools.miniterm --eol LF --dtr 0 --rts 0 --filter direct $(K210-SERIALPORT-LINUX) 115200
    endif
endif



run-k210:
	if [ ! -e "$(K210-BURNER)" ]; then (cd .. && git clone https://gitee.com/begehau/kflash.py.git && mv kflash.py tools) fi
    ifeq ($(findstring WSL, $(shell uname -a)), )
		@sudo chmod 777 $(K210-SERIALPORT-LINUX)
		python3 $(K210-BURNER) -p $(K210-SERIALPORT-LINUX) -b 1500000 $(KERNEL_BIN)
		python3 -m serial.tools.miniterm --eol LF --dtr 0 --rts 0 --filter direct $(K210-SERIALPORT-LINUX) 115200
    else
		powershell.exe 'usbipd wsl detach --all; python $(K210-BURNER) -p $(K210-SERIALPORT-WINDOWS) -b 1500000 $(KERNEL_BIN); (usbipd wsl list | findstr "$(K210-SERIALPORT-WINDOWS)") -match "\d-\d"; usbipd wsl attach --busid $$matches[0]'
		@sleep 1
		@sudo chmod 777 $(K210-SERIALPORT-LINUX)
		python3 -m serial.tools.miniterm --eol LF --dtr 0 --rts 0 --filter direct $(K210-SERIALPORT-LINUX) 115200
    endif



monitor:
	riscv64-unknown-elf-gdb -ex 'file target/riscv64gc-unknown-none-elf/debug/os' -ex 'set arch riscv:rv64' -ex 'target remote localhost:1234'

gdb:
	@qemu-system-riscv64 -machine virt -nographic -bios $(BOOTLOADER) -device loader,\
	file=target/riscv64gc-unknown-none-elf/debug/os,addr=0x80200000 -drive \
	file=$(U_FAT32),if=none,format=raw,id=x0 \
	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -smp threads=$(CORE_NUM) -S -s # file=target/riscv64gc-unknown-none-elf/$(MODE)/os,addr=0x80200000 -drive

runsimple:
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) \
		-drive file=$(U_FAT32),if=none,format=raw,id=x0 \
        -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0\
		-smp threads=$(CORE_NUM)

release: build
	@cp $(BOOTLOADER) $(BOOTLOADER).copy
	@dd if=$(KERNEL_BIN) of=$(BOOTLOADER).copy bs=$(K210_BOOTLOADER_SIZE) seek=1
	@mv $(BOOTLOADER).copy $(TOP)


easy-fs-doc:
	cd ../easy-fs/ && cargo doc --no-deps --release --document-private-items
	@cd ../os/
	@./clear_doc.sh easy-fs

os-doc:
	cargo doc --no-deps --release --target riscv64gc-unknown-none-elf --document-private-items
	@./clear_doc.sh os
.PHONY: user
