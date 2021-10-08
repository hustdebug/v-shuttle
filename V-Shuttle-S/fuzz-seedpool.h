#ifndef FUZZ_UTIL_H
#define FUZZ_UTIL_H
#include "hook-write.h"
#include "hw/pci/pci.h"
#include "hw/dma/i8257.h"

#define memory_region_init_io(mr, owner, ops, opaque, name, size); \
        hook_memory_region_init_io(mr, owner, ops, opaque, name, size);

#define isa_register_portio_list(dev, piolist, start, pio_start, opaque, name); \
        hook_isa_register_portio_list(dev, piolist, start, pio_start, opaque, name); \
        isa_register_portio_list(dev, piolist, start, pio_start, opaque, name);

#define isa_get_dma(bus, nchan) \
        hook_isa_get_dma(bus, nchan)

#define pci_dma_map(dev, addr, plen, dir) \
        hook_pci_dma_map(dev, addr, plen, dir)

#define pci_dma_unmap(dev, buffer, len, dir, access_len) \
        hook_pci_dma_unmap(dev, buffer, len, dir, access_len)

#define dma_memory_read(as, addr, buf, size, oid) \
        hook_dma_memory_read(as, addr, buf, size, oid)

#define pci_dma_read(dev, addr, buf, size, oid) \
        hook_pci_dma_read(dev, addr, buf, size, oid)

#define dma_buf_read(ptr, len, sg) \
        hook_dma_buf_read(ptr, len, sg)

#define address_space_read(as, addr, attrs, buf, size); \
        if(is_fuzzing()) {          \
            read_from_testcase(buf, len, 1);   \
        }else if(is_collecting()) {     \
            address_space_read(as, addr, attrs, buf, len);  \
            write_seed_file(buf, len, 1); \
        }

#define address_space_write(as, addr, attrs, buf, size); {}
        

#define MAX_OPS 30
#define FORKSRV_ID 198
const char access_sizes[4] = {1, 2, 4, 8};

/*          pci memory region           */
void (*read_ops[MAX_OPS])(void *opaque, hwaddr addr, unsigned size);
void (*write_ops[MAX_OPS])(void *opaque, hwaddr addr, uint64_t data, unsigned size);
void *opaque_ops[MAX_OPS];
uint32_t max_access_size[MAX_OPS];
uint32_t min_access_size[MAX_OPS];
uint32_t size_ops[MAX_OPS];
uint32_t ops_number = 0;
QEMUTimer *fuzz_timer;


/*          isa memory region           */
void (*isa_read_ops[MAX_OPS])(void *opaque, uint32_t address);
void (*isa_write_ops[MAX_OPS])(void *opaque, uint32_t address, uint32_t data);
void *isa_opaque_ops[MAX_OPS];
uint32_t isa_offset_ops[MAX_OPS];
uint32_t isa_len_ops[MAX_OPS];
unsigned isa_size_ops[MAX_OPS];
uint32_t isa_ops_number = 0;
QEMUTimer *isa_fuzz_timer;


bool setup_done = false;
bool fuzzing_mode = false;
bool collect_mode = false;
// uint64_t cur_file_offset = 0;
uint64_t cur_seed_index[50] = {0};
uint64_t exec_times = 0;

struct Callback{
    hwaddr reg;
    uint64_t val;
    unsigned index;
} ;

struct ISA_Callback{
    uint32_t reg;
    uint32_t val;
    unsigned index;
} ;

typedef enum {
    AFL_START,
    AFL_STOP
} AFL_STATES;

AFL_STATES afl_state = AFL_STOP;


void setup_process_mode(void);
void isa_setup_process_mode(void);
bool is_collecting(void);
void _afl_start(uint32_t oid);
void _afl_stop(void);


void record_write_ops(void *write, hwaddr addr, uint64_t data, unsigned size) {
    if(is_collecting()) {
        for(int i=0; i<ops_number; i++) {
            if(write == write_ops[i]) {
                struct Callback callback;
                callback.reg = addr;
                callback.val = data;
                callback.index = size;
                write_seed_file(&callback, sizeof(struct Callback), 0);
                break;
            }
        }
    }
}

void hook_memory_region_init_io(MemoryRegion *mr,
                           struct Object *owner,
                           MemoryRegionOps *ops,
                           void *opaque,
                           const char *name,
                           uint64_t size) {
    setup_process_mode();
    read_ops[ops_number] = ops->read;
    write_ops[ops_number] = ops->write;
    opaque_ops[ops_number] = opaque;
    if(ops->valid.min_access_size || ops->valid.max_access_size) {
        min_access_size[ops_number] = ops->valid.min_access_size;
        max_access_size[ops_number] = ops->valid.max_access_size;
    } else if(ops->impl.min_access_size || ops->impl.max_access_size) {
        min_access_size[ops_number] = ops->impl.min_access_size;
        max_access_size[ops_number] = ops->impl.max_access_size;
    } else {
        min_access_size[ops_number] = 1;
        max_access_size[ops_number] = 4;
    }
    size_ops[ops_number] = size;
    ops_number++;
    memory_region_init(mr, owner, name, size);
    mr->ops = ops;
    mr->opaque = opaque;
    mr->terminates = true;
}

void hook_isa_register_portio_list(ISADevice *dev,
                              PortioList *piolist, uint16_t start,
                              const MemoryRegionPortio *pio_start,
                              void *opaque, const char *name)
{
    isa_setup_process_mode();
    while (pio_start[isa_ops_number].size) {
        if(pio_start[isa_ops_number].read)
            isa_read_ops[isa_ops_number] = pio_start[isa_ops_number].read;
        if(pio_start[isa_ops_number].write)
            isa_write_ops[isa_ops_number] = pio_start[isa_ops_number].write;
        isa_opaque_ops[isa_ops_number] = opaque;
        isa_offset_ops[isa_ops_number] = pio_start[isa_ops_number].offset;
        isa_len_ops[isa_ops_number] = pio_start[isa_ops_number].len;
        isa_size_ops[isa_ops_number] = pio_start[isa_ops_number].size;
        ++isa_ops_number;
    }
}

IsaDma *hook_isa_get_dma(ISABus *bus, int nchan)
{
    assert(bus);

    I8257State *d = bus->dma[nchan > 3 ? 1 : 0];
    read_ops[ops_number] = d->channel_io.ops->read;
    write_ops[ops_number] = d->channel_io.ops->write;
    opaque_ops[ops_number] = d;
    min_access_size[ops_number] = d->channel_io.ops->impl.min_access_size;
    max_access_size[ops_number] = d->channel_io.ops->impl.max_access_size;
    size_ops[ops_number] = d->channel_io.size;
    ops_number++;

    read_ops[ops_number] = d->cont_io.ops->read;
    write_ops[ops_number] = d->cont_io.ops->write;
    opaque_ops[ops_number] = d;
    min_access_size[ops_number] = d->cont_io.ops->impl.min_access_size;
    max_access_size[ops_number] = d->cont_io.ops->impl.max_access_size;
    size_ops[ops_number] = d->cont_io.size;
    ops_number++;
    
    return bus->dma[nchan > 3 ? 1 : 0];
}

bool is_fuzzing(void) {
    return fuzzing_mode;
}

bool is_collecting(void) {
    return collect_mode;
}

void write_seed_file(void *buf, size_t buf_size, uint32_t oid) {
    FILE *fp;
    char dir[20] = {0};
    char seedName[20] = {0};

    if(cur_seed_index[oid] > 1000)
        return;

    sprintf(dir, "%d", oid);
    if (access(dir, 0) == -1) { 
        mkdir(dir, S_IRWXU);  
    }

    sprintf(seedName, "%d/seed_%ld", oid, cur_seed_index[oid]);
    fp = fopen(seedName, "ab+");
    if(fp != NULL) {
        fwrite(buf, buf_size, 1, fp);
        fclose(fp);
        printf("Write seed file : %d/seed_%ld\n", oid, cur_seed_index[oid]);
    }
    
    cur_seed_index[oid]++;
}

void read_from_testcase(void *buf, size_t buf_size, uint32_t oid) {

    switch(afl_state) {
        case AFL_START:
            _afl_stop();
            _afl_start(oid);
            afl_state = AFL_START;
            break;
        case AFL_STOP:
            _afl_start(oid);
            afl_state = AFL_START;
            break;
    }

    FILE *fp;
    size_t real_read_size;
    char seedName[30] = {0};
    sprintf(seedName, "seed/seed_%03u", oid);
    fp = fopen(seedName, "r");
    if(fp != NULL) {
        // fseek(fp, cur_file_offset, SEEK_SET);
        real_read_size = fread(buf, 1, buf_size, fp);
        // if(real_read_size != buf_size) {
        //     // cur_file_offset = 0;
        // } 
        // if(real_read_size == 0) {
        //     memset(buf, 0, buf_size);
        // }
        // cur_file_offset += real_read_size;
        fclose(fp);
    }
}

void *hook_pci_dma_map(PCIDevice *dev, dma_addr_t addr,
                                dma_addr_t *plen, DMADirection dir)
{
    if(is_fuzzing()) {
        void *buf = g_malloc0(*plen);
        read_from_testcase(buf, *plen, 2);

        return buf;
    } else {
        void *buf;

        buf = dma_memory_map(pci_get_address_space(dev), addr, plen, dir);
        return buf;
    }
}

void hook_pci_dma_unmap(PCIDevice *dev, void *buffer, dma_addr_t len,
                                 DMADirection dir, dma_addr_t access_len)
{
    if(is_fuzzing()) {
        g_free(buffer);
    } else {
        dma_memory_unmap(pci_get_address_space(dev), buffer, len, dir, access_len);
    }
}

int hook_dma_memory_read(AddressSpace *as, dma_addr_t addr,
                    const void *buf, dma_addr_t len, uint32_t oid) {
    if(is_fuzzing()) {          
        read_from_testcase(buf, len, oid); 
    }else if(is_collecting()) { 
        dma_memory_rw(as, addr, buf, len, DMA_DIRECTION_TO_DEVICE);
        write_seed_file(buf, len, oid); 
    }
    return 0;
}

int hook_pci_dma_read(PCIDevice *dev, dma_addr_t addr,
                               void *buf, dma_addr_t len, uint32_t oid)
{
    if(is_fuzzing()) {          
        read_from_testcase(buf, len, oid); 
    }else if(is_collecting()) { 
        pci_dma_rw(dev, addr, buf, len, DMA_DIRECTION_TO_DEVICE);
        write_seed_file(buf, len, oid); 
    }
    return 0;
}

static uint64_t dma_buf_rw(uint8_t *ptr, int32_t len, QEMUSGList *sg,
                           DMADirection dir)
{
    uint64_t resid;
    int sg_cur_index;

    resid = sg->size;
    sg_cur_index = 0;
    len = MIN(len, resid);
    while (len > 0) {
        ScatterGatherEntry entry = sg->sg[sg_cur_index++];
        int32_t xfer = MIN(len, entry.len);
        dma_memory_rw(sg->as, entry.base, ptr, xfer, dir);
        ptr += xfer;
        len -= xfer;
        resid -= xfer;
    }

    return resid;
}

uint64_t hook_dma_buf_read(uint8_t *ptr, int32_t len, QEMUSGList *sg)
{
    if(is_fuzzing()) {          
        read_from_testcase(ptr, len, 1); 
    }else if(is_collecting()) { 
        write_seed_file(ptr, len, 1); 
    }
    return dma_buf_rw(ptr, len, sg, DMA_DIRECTION_FROM_DEVICE);
}

int hook_address_space_read(AddressSpace *as, hwaddr addr,
                               MemTxAttrs attrs,
                               uint8_t *buf, int len)
{
    if(is_fuzzing()) {          
        read_from_testcase(buf, len, 1); 
    }else if(is_collecting()) { 
        address_space_read(as, addr, attrs, buf, len);
        write_seed_file(buf, len, 1); 
    }
    return 0;
}

void _afl_init_forkserver(void) {
    static uint8_t tmp[4];
    write(FORKSRV_ID + 1, tmp, 4);
}

void _afl_start(uint32_t oid) {
    uint32_t was_killed;
    write(FORKSRV_ID + 1, &oid, 4);
    read(FORKSRV_ID, &was_killed, 4);
}

void _afl_stop(void) {
    int status = -1;
    write(FORKSRV_ID + 1, &status, 4);
}

void fuzzing_entry(void) {
    struct Callback callback;

    unsigned access_size;
    // cur_file_offset = 0;
    for(int i=0; i<ops_number; i++) {
        read_from_testcase(&callback, sizeof(struct Callback), 0);

        access_size = access_sizes[callback.index % sizeof(access_sizes)];
        if(access_size < min_access_size[i] || access_size > max_access_size[i])
            access_size = min_access_size[i];
        read_ops[i](opaque_ops[i], callback.reg % size_ops[i] - callback.reg % access_size, access_size);
        write_ops[i](opaque_ops[i], callback.reg % size_ops[i] - callback.reg % access_size, callback.val, access_size);
    }
    timer_mod(fuzz_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    if(exec_times++>2000) {
        __gcov_flush();
        exec_times = 0;
    }
    return;
}

void setup_process_mode(void) {
    if(!setup_done) {
        fuzzing_mode = (getenv("AFL_Fuzzing") != NULL);
        collect_mode = (getenv("Collect_Corpus") != NULL);
        if(is_fuzzing()) {
            sleep(1);
            _afl_init_forkserver();
            fuzz_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, fuzzing_entry, NULL);
            timer_mod(fuzz_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        }
        setup_done = true;
    }
}

void isa_fuzzing_entry(void) {
    struct ISA_Callback callback;
    uint32_t reg;
    uint32_t val;
    // cur_file_offset = 0;
    for(int i=0; i<isa_ops_number; i++) {
        read_from_testcase(&reg, sizeof(uint32_t), 0);
        read_from_testcase(&val, sizeof(uint32_t), 0);
        reg = (reg % isa_len_ops[i]) + isa_offset_ops[i];
        val = val % (1 << (8*isa_size_ops[i]));
        if(isa_read_ops[i])
            isa_read_ops[i](isa_opaque_ops[i], reg);
        if(isa_write_ops[i])
            isa_write_ops[i](isa_opaque_ops[i], reg, val);
    }
    unsigned access_size, index;
    for(int i=0; i<ops_number; i++) {
        read_from_testcase(&reg, sizeof(uint32_t), 0);
        read_from_testcase(&val, sizeof(uint32_t), 0);
        read_from_testcase(&index, sizeof(unsigned), 0);
        access_size = access_sizes[index % sizeof(access_sizes)];
        if(access_size < min_access_size[i] || access_size > max_access_size[i])
            access_size = min_access_size[i];
        read_ops[i](opaque_ops[i], reg % size_ops[i] - reg % access_size, access_size);
        write_ops[i](opaque_ops[i], reg % size_ops[i] - reg % access_size, val, access_size);
    }
    timer_mod(isa_fuzz_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    if(exec_times++>2000) {
        __gcov_flush();
        exec_times = 0;
    }
    return;
}

void isa_setup_process_mode(void) {
    if(!setup_done) {
        fuzzing_mode = (getenv("AFL_Fuzzing") != NULL);
        collect_mode = (getenv("Collect_Corpus") != NULL);
        if(is_fuzzing()) {
            sleep(1);
            _afl_init_forkserver();
            isa_fuzz_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, isa_fuzzing_entry, NULL);
            timer_mod(isa_fuzz_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        }
        setup_done = true;
    }
}

#endif /* FUZZ_UTIL_H */