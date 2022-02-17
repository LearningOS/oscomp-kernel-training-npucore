TARGET := riscv64gc-unknown-none-elf
TESTDIR := ./user_C_program/user

build: c-user rust-user

c-user:
	cd ${TESTDIR} && make clean
	cd ${TESTDIR} && make all
	cp -r ${TESTDIR}/riscv64/ ./
	rm -r ${TESTDIR}/riscv64

rust-user: $(APPS)
	rustup target add $(TARGET)
	@cargo build --release

clean:
	@cargo clean

.PHONY: build c-user rust-user clean
