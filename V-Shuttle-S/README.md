## V-SHUTTLE Semantics-Aware Fuzzing Mode

Based on V-Shuttle main framework, we extended AFL to support seedpool targeting multiple kinds of input objects in parallel, with which we perform fine-grained semantics-aware fuzzing.

---



### 1. Setup

**Compile AFL**

```bash
cd afl-seedpool
make
make install
```

**Compile QEMU**

- Get QEMU source code (Take [QEMU 5.1.0](https://download.qemu.org/qemu-5.1.0.tar.xz) as an example)

- Move `fuzz-seedpool.h` and `hook-write.h` to QEMU_DIR/include

- Move `memory.c` to QEMU_DIR/softmmu

- Apply our [patches](https://github.com/hustdebug/v-shuttle/tree/main/V-Shuttle-S/QEMU-patch) (such as [hcd-ohci](https://github.com/hustdebug/v-shuttle/blob/main/V-Shuttle-S/QEMU-patch/hcd-ohci.patch)) to enable type awareness

- Compile QEMU

```bash
./configure --enable-debug --enable-sanitizers --enable-gcov --cc=afl-gcc --target-list=x86_64-softmmu
make -j8
```

- Create input and output directory

```
mkdir in out seed
```

### 2. Collect seeds（optional）

Take hcd-ohci as an exmaple

```bash
../collect_seeds.sh
```

### 3. Fuzzing

Take hcd-ohci as an exmaple

```bash
./fuzz.sh
```

