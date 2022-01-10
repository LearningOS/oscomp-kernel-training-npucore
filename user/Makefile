TARGET := riscv64gc-unknown-none-elf
APP_DIR := src/bin
APPS := $(wildcard $(APP_DIR)/*.rs)
TESTDIR := ./user_C_program/user
RELEASE_DIR := target/$(TARGET)/release
DEBUG_DIR := target/$(TARGET)/debug
RELEASE_ELFS := $(patsubst $(APP_DIR)/%.rs, $(RELEASE_DIR)/%, $(APPS))
DEBUG_ELFS := $(patsubst $(APP_DIR)/%.rs, $(DEBUG_DIR)/%, $(APPS))

OBJDUMP := rust-objdump --arch-name=riscv64
OBJCOPY := rust-objcopy --binary-architecture=riscv64

build: update binary debug

# for "user_C_program"
update:
	cd ${TESTDIR} && make clean
	cd ${TESTDIR} && make all
	cp -r ${TESTDIR}/riscv64/ ./
	rm -r ${TESTDIR}/riscv64

# for "src"
elf: $(APPS)
	rustup target add $(TARGET)
	@cargo build --release
	@cargo build

binary: elf
	$(foreach elf, $(RELEASE_ELFS), $(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(RELEASE_DIR)/%, $(RELEASE_DIR)/%.bin, $(elf));)

debug: elf
	@mkdir -p ../os/user && cp $(DEBUG_ELFS) ../os/user

clean:
	@cargo clean

.PHONY: build elf binary debug clean
