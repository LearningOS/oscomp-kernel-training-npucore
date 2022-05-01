    .section .data
    .global sinitproc
    .global einitproc
    .align 12
sinitproc:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/initproc"
einitproc:
    .align 12

    .section .data
    .global sbash
    .global ebash
    .align 12
sbash:
    .incbin "../bash-5.1.16/bash"
ebash:
    .align 12




