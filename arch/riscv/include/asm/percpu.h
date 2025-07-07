#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

static inline void set_my_cpu_offset(unsigned long off)
{
	csr_write(CSR_SCRATCH, off);
}

#define __my_cpu_offset csr_read(CSR_SCRATCH)

#include <asm-generic/percpu.h>

#endif
