

## V-SHUTTLE Main Framework

We patched AFL to selectively instrument device-related code in the QEMU, and disable forkserver-related code to support persistent fuzzing mode. Every time when testing a kind of device, you are supposed to insert macros into the target device’s source code and recompile QEMU.



### 1. Setup

**Compile AFL**

```bash
cd afl-2.52b
make
make install
```

**Compile QEMU**

- Get QEMU source code (Take [QEMU 5.1.0](https://download.qemu.org/qemu-5.1.0.tar.xz) as an example)

- Move `fuzz-util.h` and `hook-write.h` to QEMU_DIR/include

- Move `memory.c` to QEMU_DIR/softmmu

- Insert `#include "fuzz-util.h"` into the target device's code (depends on what device to test, such as QEMU_DIR/hw/usb/hcd-ohci.c)

- Compile QEMU

```bash
./configure --enable-debug --enable-sanitizers --enable-gcov --cc=afl-gcc --target-list=x86_64-softmmu
make -j8

mkdir in out
touch seed_file
```

### 2. Collect seeds（optional）

Take hcd-ohci as an exmaple

```bash
./collect_seeds.sh
```

### 3. Fuzzing

Take hcd-ohci as an exmaple

```bash
./fuzz.sh
```

### Tips:
1. Ignore the errors reported in AFL compilation ("Oops the instrumentation dose not seem to be behaving correctly"). This is because we selectively instrument virtual devices of hypervisor, so the demo program was not included.
2. We suggest attaching `gdb` to the QEMU process when you run V-shuttle to fuzz the QEMU. If you run v-shuttle within a few minutes and encounter "unable to communicate with fork server (OOM?)", this is not surprising, which means that you have found the crash, and you can see the details of the crash in `gdb`. The reason is that our tool currently does not support to save complete test cases in persistent mode. If you encounter a crash, you may need to restart the fuzzing application again :(. Since crashes rarely occur in virtual devices, and each crash deserves detailed analysis, Therefore, we believe that this will not affect V-shuttle's ability to find vulnerabilities. Hope you have fun using V-shuttle.



