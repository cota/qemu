#include "qemu/osdep.h"

#include "cpus-common-shim.h"

CPUTailQ cpus = QTAILQ_HEAD_INITIALIZER(cpus);
__thread CPUState *current_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return qemu_thread_is_self(cpu->thread);
}

void qemu_cpu_kick(CPUState *cpu) {}

#ifdef CONFIG_PLUGIN
void qemu_plugin_vcpu_exit_hook(CPUState *cpu) {}
#endif

void cpus_common_shim_init(void) {
    qemu_init_cpu_list();
}
