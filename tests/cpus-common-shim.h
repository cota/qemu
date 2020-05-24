/* Include this file to link cpus-common.o in a unit test */
#ifndef CPUS_COMMON_SHIM_H
#define CPUS_COMMON_SHIM_H

#include "hw/core/cpu.h"
#include "exec/cpu-common.h"

extern void cpus_common_shim_init(void);

#endif /* CPUS_COMMON_SHIM_H */
