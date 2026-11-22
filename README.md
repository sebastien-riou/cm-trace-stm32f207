# cm-trace-stm32f207

> [!WARNING]
> **Deprecated.** This repository is no longer maintained. cm-trace now runs on the STM32F207 Nucleo board as a
> [lean-bsp](https://github.com/sebastien-riou/lean-bsp) application:
> [cm-trace](https://github.com/sebastien-riou/cm-trace) built with
> [lean-bsp-nucleo-f207](https://github.com/sebastien-riou/lean-bsp-nucleo-f207), a board support package shared by
> every lean-bsp application. Follow cm-trace's README, section
> ["With lean-bsp"](https://github.com/sebastien-riou/cm-trace#with-lean-bsp).
>
> That build traces the same as this project, instruction for instruction (opcode and cycles), and also runs on other
> boards. This repository stays as it was, for reference.

Cycle accurate trace on STM32F207 using [cm-trace](https://github.com/sebastien-riou/cm-trace).

## Instead: the lean-bsp build

With `cm-trace`, `lean-bsp-nucleo-f207` and [lean-hwbridge](https://github.com/sebastien-riou/lean-hwbridge) set up
as cm-trace's README describes, from the `cm-trace` directory:

````
lbsp build --bsp nucleo-f207
lbsp load --bsp nucleo-f207
pipenv run python -m cmtrace.capture /dev/ttyACM0 build/nucleo-f207/cortex-m3/cm-trace.elf --setup=test_umul64_16_16 umul64
````

The instructions below are this repository's own, kept as they were.

## Setup
This projected as been tested with https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack/releases/tag/v14.2.1-1.1 on Ubuntu 24.04.

Connect STM32F207 Nucleo board such that it appears as '/dev/ttyACM0'.

````
./initial-setup
````

Expected output:
````
...
+ pipenv run cmtrace-capture /dev/ttyACM0 build/cmtrace-stm32f207.elf --setup=test_umul64_16_16 umul64
2026-05-16 16:28:17.743 INFO:	PC=0x08001f1e: 2 muls
2026-05-16 16:28:17.744 INFO:	PC=0x08001f20: 2 mla
2026-05-16 16:28:17.744 INFO:	PC=0x08001f24: 3 umull
2026-05-16 16:28:17.745 INFO:	PC=0x08001f28: 1 add
2026-05-16 16:28:17.745 INFO:	PC=0x08001f2a: 1 bx
umul64: 5 instructions, 9 cycles
````

## How to use

### Add function to trace
See [cm-trace](https://github.com/sebastien-riou/cm-trace).

### Build
````
make clean all
````

### Flash the board
````
./flash
````

### Capture
The following creates a `.cmtrace` file which contains a copy of the elf file and the execution trace:
````
pipenv run cmtrace-capture /dev/ttyACM0 build/cmtrace-stm32f207.elf [--setup=<test function name>] <target function name>
````

### Dump, cycles breakdown by functions... 
See [cm-trace](https://github.com/sebastien-riou/cm-trace).