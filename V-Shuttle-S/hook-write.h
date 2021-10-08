#ifndef HOOK_WRITE_H
#define HOOK_WRITE_H


void record_write_ops(void *write, hwaddr addr, uint64_t data, unsigned size);

#endif /* HOOK_WRITE_H */