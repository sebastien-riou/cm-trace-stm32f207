# cm-trace-stm32f207
Cycle accurate trace on STM32F207

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
