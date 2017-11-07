/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * Copyright (c) 2004-2007 Fabrice Bellard
 * Copyright (c) 2007 Jocelyn Mayer
 * Copyright (c) 2010 David Gibson, IBM Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "sysemu/sysemu.h"
#include "sysemu/numa.h"
#include "hw/hw.h"
#include "qemu/log.h"
#include "hw/fw-path-provider.h"
#include "elf.h"
#include "net/net.h"
#include "sysemu/device_tree.h"
#include "sysemu/block-backend.h"
#include "sysemu/cpus.h"
#include "sysemu/hw_accel.h"
#include "kvm_ppc.h"
#include "migration/misc.h"
#include "migration/global_state.h"
#include "migration/register.h"
#include "mmu-hash64.h"
#include "mmu-book3s-v3.h"
#include "cpu-models.h"
#include "qom/cpu.h"

#include "hw/boards.h"
#include "hw/ppc/ppc.h"
#include "hw/loader.h"

#include "hw/ppc/fdt.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_vio.h"
#include "hw/pci-host/spapr.h"
#include "hw/ppc/xics.h"
#include "hw/pci/msi.h"

#include "hw/pci/pci.h"
#include "hw/scsi/scsi.h"
#include "hw/virtio/virtio-scsi.h"
#include "hw/virtio/vhost-scsi-common.h"

#include "exec/address-spaces.h"
#include "hw/usb.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "trace.h"
#include "hw/nmi.h"
#include "hw/intc/intc.h"

#include "hw/compat.h"
#include "qemu/cutils.h"
#include "hw/ppc/spapr_cpu_core.h"

#include <libfdt.h>

/* SLOF memory layout:
 *
 * SLOF raw image loaded at 0, copies its romfs right below the flat
 * device-tree, then position SLOF itself 31M below that
 *
 * So we set FW_OVERHEAD to 40MB which should account for all of that
 * and more
 *
 * We load our kernel at 4M, leaving space for SLOF initial image
 */
#define FDT_MAX_SIZE            0x100000
#define RTAS_MAX_SIZE           0x10000
#define RTAS_MAX_ADDR           0x80000000 /* RTAS must stay below that */
#define FW_MAX_SIZE             0x400000
#define FW_FILE_NAME            "slof.bin"
#define FW_OVERHEAD             0x2800000
#define KERNEL_LOAD_ADDR        FW_MAX_SIZE

#define MIN_RMA_SLOF            128UL

#define PHANDLE_XICP            0x00001111

/* These two functions implement the VCPU id numbering: one to compute them
 * all and one to identify thread 0 of a VCORE. Any change to the first one
 * is likely to have an impact on the second one, so let's keep them close.
 */
static int spapr_vcpu_id(sPAPRMachineState *spapr, int cpu_index)
{
    return
        (cpu_index / smp_threads) * spapr->vsmt + cpu_index % smp_threads;
}
static bool spapr_is_thread0_in_vcore(sPAPRMachineState *spapr,
                                      PowerPCCPU *cpu)
{
    return spapr_get_vcpu_id(cpu) % spapr->vsmt == 0;
}

static ICSState *spapr_ics_create(sPAPRMachineState *spapr,
                                  const char *type_ics,
                                  int nr_irqs, Error **errp)
{
    Error *local_err = NULL;
    Object *obj;

    obj = object_new(type_ics);
    object_property_add_child(OBJECT(spapr), "ics", obj, &error_abort);
    object_property_add_const_link(obj, ICS_PROP_XICS, OBJECT(spapr),
                                   &error_abort);
    object_property_set_int(obj, nr_irqs, "nr-irqs", &local_err);
    if (local_err) {
        goto error;
    }
    object_property_set_bool(obj, true, "realized", &local_err);
    if (local_err) {
        goto error;
    }

    return ICS_SIMPLE(obj);

error:
    error_propagate(errp, local_err);
    return NULL;
}

static bool pre_2_10_vmstate_dummy_icp_needed(void *opaque)
{
    /* Dummy entries correspond to unused ICPState objects in older QEMUs,
     * and newer QEMUs don't even have them. In both cases, we don't want
     * to send anything on the wire.
     */
    return false;
}

static const VMStateDescription pre_2_10_vmstate_dummy_icp = {
    .name = "icp/server",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = pre_2_10_vmstate_dummy_icp_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UNUSED(4), /* uint32_t xirr */
        VMSTATE_UNUSED(1), /* uint8_t pending_priority */
        VMSTATE_UNUSED(1), /* uint8_t mfrr */
        VMSTATE_END_OF_LIST()
    },
};

static void pre_2_10_vmstate_register_dummy_icp(int i)
{
    vmstate_register(NULL, i, &pre_2_10_vmstate_dummy_icp,
                     (void *)(uintptr_t) i);
}

static void pre_2_10_vmstate_unregister_dummy_icp(int i)
{
    vmstate_unregister(NULL, &pre_2_10_vmstate_dummy_icp,
                       (void *)(uintptr_t) i);
}

static int xics_max_server_number(sPAPRMachineState *spapr)
{
    return DIV_ROUND_UP(max_cpus * spapr->vsmt, smp_threads);
}

static void xics_system_init(MachineState *machine, int nr_irqs, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(machine);
    sPAPRMachineClass *smc = SPAPR_MACHINE_GET_CLASS(machine);

    if (kvm_enabled()) {
        if (machine_kernel_irqchip_allowed(machine) &&
            !xics_kvm_init(spapr, errp)) {
            spapr->icp_type = TYPE_KVM_ICP;
            spapr->ics = spapr_ics_create(spapr, TYPE_ICS_KVM, nr_irqs, errp);
        }
        if (machine_kernel_irqchip_required(machine) && !spapr->ics) {
            error_prepend(errp, "kernel_irqchip requested but unavailable: ");
            return;
        }
    }

    if (!spapr->ics) {
        xics_spapr_init(spapr);
        spapr->icp_type = TYPE_ICP;
        spapr->ics = spapr_ics_create(spapr, TYPE_ICS_SIMPLE, nr_irqs, errp);
        if (!spapr->ics) {
            return;
        }
    }

    if (smc->pre_2_10_has_unused_icps) {
        int i;

        for (i = 0; i < xics_max_server_number(spapr); i++) {
            /* Dummy entries get deregistered when real ICPState objects
             * are registered during CPU core hotplug.
             */
            pre_2_10_vmstate_register_dummy_icp(i);
        }
    }
}

static int spapr_fixup_cpu_smt_dt(void *fdt, int offset, PowerPCCPU *cpu,
                                  int smt_threads)
{
    int i, ret = 0;
    uint32_t servers_prop[smt_threads];
    uint32_t gservers_prop[smt_threads * 2];
    int index = spapr_get_vcpu_id(cpu);

    if (cpu->compat_pvr) {
        ret = fdt_setprop_cell(fdt, offset, "cpu-version", cpu->compat_pvr);
        if (ret < 0) {
            return ret;
        }
    }

    /* Build interrupt servers and gservers properties */
    for (i = 0; i < smt_threads; i++) {
        servers_prop[i] = cpu_to_be32(index + i);
        /* Hack, direct the group queues back to cpu 0 */
        gservers_prop[i*2] = cpu_to_be32(index + i);
        gservers_prop[i*2 + 1] = 0;
    }
    ret = fdt_setprop(fdt, offset, "ibm,ppc-interrupt-server#s",
                      servers_prop, sizeof(servers_prop));
    if (ret < 0) {
        return ret;
    }
    ret = fdt_setprop(fdt, offset, "ibm,ppc-interrupt-gserver#s",
                      gservers_prop, sizeof(gservers_prop));

    return ret;
}

static int spapr_fixup_cpu_numa_dt(void *fdt, int offset, PowerPCCPU *cpu)
{
    int index = spapr_get_vcpu_id(cpu);
    uint32_t associativity[] = {cpu_to_be32(0x5),
                                cpu_to_be32(0x0),
                                cpu_to_be32(0x0),
                                cpu_to_be32(0x0),
                                cpu_to_be32(cpu->node_id),
                                cpu_to_be32(index)};

    /* Advertise NUMA via ibm,associativity */
    return fdt_setprop(fdt, offset, "ibm,associativity", associativity,
                          sizeof(associativity));
}

/* Populate the "ibm,pa-features" property */
static void spapr_populate_pa_features(sPAPRMachineState *spapr,
                                       PowerPCCPU *cpu,
                                       void *fdt, int offset,
                                       bool legacy_guest)
{
    CPUPPCState *env = &cpu->env;
    uint8_t pa_features_206[] = { 6, 0,
        0xf6, 0x1f, 0xc7, 0x00, 0x80, 0xc0 };
    uint8_t pa_features_207[] = { 24, 0,
        0xf6, 0x1f, 0xc7, 0xc0, 0x80, 0xf0,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x80, 0x00, 0x80, 0x00, 0x00, 0x00 };
    uint8_t pa_features_300[] = { 66, 0,
        /* 0: MMU|FPU|SLB|RUN|DABR|NX, 1: fri[nzpm]|DABRX|SPRG3|SLB0|PP110 */
        /* 2: VPM|DS205|PPR|DS202|DS206, 3: LSD|URG, SSO, 5: LE|CFAR|EB|LSQ */
        0xf6, 0x1f, 0xc7, 0xc0, 0x80, 0xf0, /* 0 - 5 */
        /* 6: DS207 */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, /* 6 - 11 */
        /* 16: Vector */
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, /* 12 - 17 */
        /* 18: Vec. Scalar, 20: Vec. XOR, 22: HTM */
        0x80, 0x00, 0x80, 0x00, 0x00, 0x00, /* 18 - 23 */
        /* 24: Ext. Dec, 26: 64 bit ftrs, 28: PM ftrs */
        0x80, 0x00, 0x80, 0x00, 0x80, 0x00, /* 24 - 29 */
        /* 30: MMR, 32: LE atomic, 34: EBB + ext EBB */
        0x80, 0x00, 0x80, 0x00, 0xC0, 0x00, /* 30 - 35 */
        /* 36: SPR SO, 38: Copy/Paste, 40: Radix MMU */
        0x80, 0x00, 0x80, 0x00, 0x80, 0x00, /* 36 - 41 */
        /* 42: PM, 44: PC RA, 46: SC vec'd */
        0x80, 0x00, 0x80, 0x00, 0x80, 0x00, /* 42 - 47 */
        /* 48: SIMD, 50: QP BFP, 52: String */
        0x80, 0x00, 0x80, 0x00, 0x80, 0x00, /* 48 - 53 */
        /* 54: DecFP, 56: DecI, 58: SHA */
        0x80, 0x00, 0x80, 0x00, 0x80, 0x00, /* 54 - 59 */
        /* 60: NM atomic, 62: RNG */
        0x80, 0x00, 0x80, 0x00, 0x00, 0x00, /* 60 - 65 */
    };
    uint8_t *pa_features = NULL;
    size_t pa_size;

    if (ppc_check_compat(cpu, CPU_POWERPC_LOGICAL_2_06, 0, cpu->compat_pvr)) {
        pa_features = pa_features_206;
        pa_size = sizeof(pa_features_206);
    }
    if (ppc_check_compat(cpu, CPU_POWERPC_LOGICAL_2_07, 0, cpu->compat_pvr)) {
        pa_features = pa_features_207;
        pa_size = sizeof(pa_features_207);
    }
    if (ppc_check_compat(cpu, CPU_POWERPC_LOGICAL_3_00, 0, cpu->compat_pvr)) {
        pa_features = pa_features_300;
        pa_size = sizeof(pa_features_300);
    }
    if (!pa_features) {
        return;
    }

    if (env->ci_large_pages) {
        /*
         * Note: we keep CI large pages off by default because a 64K capable
         * guest provisioned with large pages might otherwise try to map a qemu
         * framebuffer (or other kind of memory mapped PCI BAR) using 64K pages
         * even if that qemu runs on a 4k host.
         * We dd this bit back here if we are confident this is not an issue
         */
        pa_features[3] |= 0x20;
    }
    if ((spapr_get_cap(spapr, SPAPR_CAP_HTM) != 0) && pa_size > 24) {
        pa_features[24] |= 0x80;    /* Transactional memory support */
    }
    if (legacy_guest && pa_size > 40) {
        /* Workaround for broken kernels that attempt (guest) radix
         * mode when they can't handle it, if they see the radix bit set
         * in pa-features. So hide it from them. */
        pa_features[40 + 2] &= ~0x80; /* Radix MMU */
    }

    _FDT((fdt_setprop(fdt, offset, "ibm,pa-features", pa_features, pa_size)));
}

static int spapr_fixup_cpu_dt(void *fdt, sPAPRMachineState *spapr)
{
    int ret = 0, offset, cpus_offset;
    CPUState *cs;
    char cpu_model[32];
    uint32_t pft_size_prop[] = {0, cpu_to_be32(spapr->htab_shift)};

    CPU_FOREACH(cs) {
        PowerPCCPU *cpu = POWERPC_CPU(cs);
        DeviceClass *dc = DEVICE_GET_CLASS(cs);
        int index = spapr_get_vcpu_id(cpu);
        int compat_smt = MIN(smp_threads, ppc_compat_max_vthreads(cpu));

        if (!spapr_is_thread0_in_vcore(spapr, cpu)) {
            continue;
        }

        snprintf(cpu_model, 32, "%s@%x", dc->fw_name, index);

        cpus_offset = fdt_path_offset(fdt, "/cpus");
        if (cpus_offset < 0) {
            cpus_offset = fdt_add_subnode(fdt, 0, "cpus");
            if (cpus_offset < 0) {
                return cpus_offset;
            }
        }
        offset = fdt_subnode_offset(fdt, cpus_offset, cpu_model);
        if (offset < 0) {
            offset = fdt_add_subnode(fdt, cpus_offset, cpu_model);
            if (offset < 0) {
                return offset;
            }
        }

        ret = fdt_setprop(fdt, offset, "ibm,pft-size",
                          pft_size_prop, sizeof(pft_size_prop));
        if (ret < 0) {
            return ret;
        }

        if (nb_numa_nodes > 1) {
            ret = spapr_fixup_cpu_numa_dt(fdt, offset, cpu);
            if (ret < 0) {
                return ret;
            }
        }

        ret = spapr_fixup_cpu_smt_dt(fdt, offset, cpu, compat_smt);
        if (ret < 0) {
            return ret;
        }

        spapr_populate_pa_features(spapr, cpu, fdt, offset,
                                   spapr->cas_legacy_guest_workaround);
    }
    return ret;
}

static hwaddr spapr_node0_size(MachineState *machine)
{
    if (nb_numa_nodes) {
        int i;
        for (i = 0; i < nb_numa_nodes; ++i) {
            if (numa_info[i].node_mem) {
                return MIN(pow2floor(numa_info[i].node_mem),
                           machine->ram_size);
            }
        }
    }
    return machine->ram_size;
}

static void add_str(GString *s, const gchar *s1)
{
    g_string_append_len(s, s1, strlen(s1) + 1);
}

static int spapr_populate_memory_node(void *fdt, int nodeid, hwaddr start,
                                       hwaddr size)
{
    uint32_t associativity[] = {
        cpu_to_be32(0x4), /* length */
        cpu_to_be32(0x0), cpu_to_be32(0x0),
        cpu_to_be32(0x0), cpu_to_be32(nodeid)
    };
    char mem_name[32];
    uint64_t mem_reg_property[2];
    int off;

    mem_reg_property[0] = cpu_to_be64(start);
    mem_reg_property[1] = cpu_to_be64(size);

    sprintf(mem_name, "memory@" TARGET_FMT_lx, start);
    off = fdt_add_subnode(fdt, 0, mem_name);
    _FDT(off);
    _FDT((fdt_setprop_string(fdt, off, "device_type", "memory")));
    _FDT((fdt_setprop(fdt, off, "reg", mem_reg_property,
                      sizeof(mem_reg_property))));
    _FDT((fdt_setprop(fdt, off, "ibm,associativity", associativity,
                      sizeof(associativity))));
    return off;
}

static int spapr_populate_memory(sPAPRMachineState *spapr, void *fdt)
{
    MachineState *machine = MACHINE(spapr);
    hwaddr mem_start, node_size;
    int i, nb_nodes = nb_numa_nodes;
    NodeInfo *nodes = numa_info;
    NodeInfo ramnode;

    /* No NUMA nodes, assume there is just one node with whole RAM */
    if (!nb_numa_nodes) {
        nb_nodes = 1;
        ramnode.node_mem = machine->ram_size;
        nodes = &ramnode;
    }

    for (i = 0, mem_start = 0; i < nb_nodes; ++i) {
        if (!nodes[i].node_mem) {
            continue;
        }
        if (mem_start >= machine->ram_size) {
            node_size = 0;
        } else {
            node_size = nodes[i].node_mem;
            if (node_size > machine->ram_size - mem_start) {
                node_size = machine->ram_size - mem_start;
            }
        }
        if (!mem_start) {
            /* spapr_machine_init() checks for rma_size <= node0_size
             * already */
            spapr_populate_memory_node(fdt, i, 0, spapr->rma_size);
            mem_start += spapr->rma_size;
            node_size -= spapr->rma_size;
        }
        for ( ; node_size; ) {
            hwaddr sizetmp = pow2floor(node_size);

            /* mem_start != 0 here */
            if (ctzl(mem_start) < ctzl(sizetmp)) {
                sizetmp = 1ULL << ctzl(mem_start);
            }

            spapr_populate_memory_node(fdt, i, mem_start, sizetmp);
            node_size -= sizetmp;
            mem_start += sizetmp;
        }
    }

    return 0;
}

static void spapr_populate_cpu_dt(CPUState *cs, void *fdt, int offset,
                                  sPAPRMachineState *spapr)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cs);
    int index = spapr_get_vcpu_id(cpu);
    uint32_t segs[] = {cpu_to_be32(28), cpu_to_be32(40),
                       0xffffffff, 0xffffffff};
    uint32_t tbfreq = kvm_enabled() ? kvmppc_get_tbfreq()
        : SPAPR_TIMEBASE_FREQ;
    uint32_t cpufreq = kvm_enabled() ? kvmppc_get_clockfreq() : 1000000000;
    uint32_t page_sizes_prop[64];
    size_t page_sizes_prop_size;
    uint32_t vcpus_per_socket = smp_threads * smp_cores;
    uint32_t pft_size_prop[] = {0, cpu_to_be32(spapr->htab_shift)};
    int compat_smt = MIN(smp_threads, ppc_compat_max_vthreads(cpu));
    sPAPRDRConnector *drc;
    int drc_index;
    uint32_t radix_AP_encodings[PPC_PAGE_SIZES_MAX_SZ];
    int i;

    drc = spapr_drc_by_id(TYPE_SPAPR_DRC_CPU, index);
    if (drc) {
        drc_index = spapr_drc_index(drc);
        _FDT((fdt_setprop_cell(fdt, offset, "ibm,my-drc-index", drc_index)));
    }

    _FDT((fdt_setprop_cell(fdt, offset, "reg", index)));
    _FDT((fdt_setprop_string(fdt, offset, "device_type", "cpu")));

    _FDT((fdt_setprop_cell(fdt, offset, "cpu-version", env->spr[SPR_PVR])));
    _FDT((fdt_setprop_cell(fdt, offset, "d-cache-block-size",
                           env->dcache_line_size)));
    _FDT((fdt_setprop_cell(fdt, offset, "d-cache-line-size",
                           env->dcache_line_size)));
    _FDT((fdt_setprop_cell(fdt, offset, "i-cache-block-size",
                           env->icache_line_size)));
    _FDT((fdt_setprop_cell(fdt, offset, "i-cache-line-size",
                           env->icache_line_size)));

    if (pcc->l1_dcache_size) {
        _FDT((fdt_setprop_cell(fdt, offset, "d-cache-size",
                               pcc->l1_dcache_size)));
    } else {
        warn_report("Unknown L1 dcache size for cpu");
    }
    if (pcc->l1_icache_size) {
        _FDT((fdt_setprop_cell(fdt, offset, "i-cache-size",
                               pcc->l1_icache_size)));
    } else {
        warn_report("Unknown L1 icache size for cpu");
    }

    _FDT((fdt_setprop_cell(fdt, offset, "timebase-frequency", tbfreq)));
    _FDT((fdt_setprop_cell(fdt, offset, "clock-frequency", cpufreq)));
    _FDT((fdt_setprop_cell(fdt, offset, "slb-size", env->slb_nr)));
    _FDT((fdt_setprop_cell(fdt, offset, "ibm,slb-size", env->slb_nr)));
    _FDT((fdt_setprop_string(fdt, offset, "status", "okay")));
    _FDT((fdt_setprop(fdt, offset, "64-bit", NULL, 0)));

    if (env->spr_cb[SPR_PURR].oea_read) {
        _FDT((fdt_setprop(fdt, offset, "ibm,purr", NULL, 0)));
    }

    if (env->mmu_model & POWERPC_MMU_1TSEG) {
        _FDT((fdt_setprop(fdt, offset, "ibm,processor-segment-sizes",
                          segs, sizeof(segs))));
    }

    /* Advertise VSX (vector extensions) if available
     *   1               == VMX / Altivec available
     *   2               == VSX available
     *
     * Only CPUs for which we create core types in spapr_cpu_core.c
     * are possible, and all of those have VMX */
    if (spapr_get_cap(spapr, SPAPR_CAP_VSX) != 0) {
        _FDT((fdt_setprop_cell(fdt, offset, "ibm,vmx", 2)));
    } else {
        _FDT((fdt_setprop_cell(fdt, offset, "ibm,vmx", 1)));
    }

    /* Advertise DFP (Decimal Floating Point) if available
     *   0 / no property == no DFP
     *   1               == DFP available */
    if (spapr_get_cap(spapr, SPAPR_CAP_DFP) != 0) {
        _FDT((fdt_setprop_cell(fdt, offset, "ibm,dfp", 1)));
    }

    page_sizes_prop_size = ppc_create_page_sizes_prop(env, page_sizes_prop,
                                                  sizeof(page_sizes_prop));
    if (page_sizes_prop_size) {
        _FDT((fdt_setprop(fdt, offset, "ibm,segment-page-sizes",
                          page_sizes_prop, page_sizes_prop_size)));
    }

    spapr_populate_pa_features(spapr, cpu, fdt, offset, false);

    _FDT((fdt_setprop_cell(fdt, offset, "ibm,chip-id",
                           cs->cpu_index / vcpus_per_socket)));

    _FDT((fdt_setprop(fdt, offset, "ibm,pft-size",
                      pft_size_prop, sizeof(pft_size_prop))));

    if (nb_numa_nodes > 1) {
        _FDT(spapr_fixup_cpu_numa_dt(fdt, offset, cpu));
    }

    _FDT(spapr_fixup_cpu_smt_dt(fdt, offset, cpu, compat_smt));

    if (pcc->radix_page_info) {
        for (i = 0; i < pcc->radix_page_info->count; i++) {
            radix_AP_encodings[i] =
                cpu_to_be32(pcc->radix_page_info->entries[i]);
        }
        _FDT((fdt_setprop(fdt, offset, "ibm,processor-radix-AP-encodings",
                          radix_AP_encodings,
                          pcc->radix_page_info->count *
                          sizeof(radix_AP_encodings[0]))));
    }
}

static void spapr_populate_cpus_dt_node(void *fdt, sPAPRMachineState *spapr)
{
    CPUState **rev;
    CPUState *cs;
    int n_cpus;
    int cpus_offset;
    char *nodename;
    int i;

    cpus_offset = fdt_add_subnode(fdt, 0, "cpus");
    _FDT(cpus_offset);
    _FDT((fdt_setprop_cell(fdt, cpus_offset, "#address-cells", 0x1)));
    _FDT((fdt_setprop_cell(fdt, cpus_offset, "#size-cells", 0x0)));

    /*
     * We walk the CPUs in reverse order to ensure that CPU DT nodes
     * created by fdt_add_subnode() end up in the right order in FDT
     * for the guest kernel the enumerate the CPUs correctly.
     *
     * The CPU list cannot be traversed in reverse order, so we need
     * to do extra work.
     */
    n_cpus = 0;
    rev = NULL;
    CPU_FOREACH(cs) {
        rev = g_renew(CPUState *, rev, n_cpus + 1);
        rev[n_cpus++] = cs;
    }

    for (i = n_cpus - 1; i >= 0; i--) {
        CPUState *cs = rev[i];
        PowerPCCPU *cpu = POWERPC_CPU(cs);
        int index = spapr_get_vcpu_id(cpu);
        DeviceClass *dc = DEVICE_GET_CLASS(cs);
        int offset;

        if (!spapr_is_thread0_in_vcore(spapr, cpu)) {
            continue;
        }

        nodename = g_strdup_printf("%s@%x", dc->fw_name, index);
        offset = fdt_add_subnode(fdt, cpus_offset, nodename);
        g_free(nodename);
        _FDT(offset);
        spapr_populate_cpu_dt(cs, fdt, offset, spapr);
    }

}

static uint32_t spapr_pc_dimm_node(MemoryDeviceInfoList *list, ram_addr_t addr)
{
    MemoryDeviceInfoList *info;

    for (info = list; info; info = info->next) {
        MemoryDeviceInfo *value = info->value;

        if (value && value->type == MEMORY_DEVICE_INFO_KIND_DIMM) {
            PCDIMMDeviceInfo *pcdimm_info = value->u.dimm.data;

            if (pcdimm_info->addr >= addr &&
                addr < (pcdimm_info->addr + pcdimm_info->size)) {
                return pcdimm_info->node;
            }
        }
    }

    return -1;
}

/*
 * Adds ibm,dynamic-reconfiguration-memory node.
 * Refer to docs/specs/ppc-spapr-hotplug.txt for the documentation
 * of this device tree node.
 */
static int spapr_populate_drconf_memory(sPAPRMachineState *spapr, void *fdt)
{
    MachineState *machine = MACHINE(spapr);
    int ret, i, offset;
    uint64_t lmb_size = SPAPR_MEMORY_BLOCK_SIZE;
    uint32_t prop_lmb_size[] = {0, cpu_to_be32(lmb_size)};
    uint32_t hotplug_lmb_start = spapr->hotplug_memory.base / lmb_size;
    uint32_t nr_lmbs = (spapr->hotplug_memory.base +
                       memory_region_size(&spapr->hotplug_memory.mr)) /
                       lmb_size;
    uint32_t *int_buf, *cur_index, buf_len;
    int nr_nodes = nb_numa_nodes ? nb_numa_nodes : 1;
    MemoryDeviceInfoList *dimms = NULL;

    /*
     * Don't create the node if there is no hotpluggable memory
     */
    if (machine->ram_size == machine->maxram_size) {
        return 0;
    }

    /*
     * Allocate enough buffer size to fit in ibm,dynamic-memory
     * or ibm,associativity-lookup-arrays
     */
    buf_len = MAX(nr_lmbs * SPAPR_DR_LMB_LIST_ENTRY_SIZE + 1, nr_nodes * 4 + 2)
              * sizeof(uint32_t);
    cur_index = int_buf = g_malloc0(buf_len);

    offset = fdt_add_subnode(fdt, 0, "ibm,dynamic-reconfiguration-memory");

    ret = fdt_setprop(fdt, offset, "ibm,lmb-size", prop_lmb_size,
                    sizeof(prop_lmb_size));
    if (ret < 0) {
        goto out;
    }

    ret = fdt_setprop_cell(fdt, offset, "ibm,memory-flags-mask", 0xff);
    if (ret < 0) {
        goto out;
    }

    ret = fdt_setprop_cell(fdt, offset, "ibm,memory-preservation-time", 0x0);
    if (ret < 0) {
        goto out;
    }

    if (hotplug_lmb_start) {
        MemoryDeviceInfoList **prev = &dimms;
        qmp_pc_dimm_device_list(qdev_get_machine(), &prev);
    }

    /* ibm,dynamic-memory */
    int_buf[0] = cpu_to_be32(nr_lmbs);
    cur_index++;
    for (i = 0; i < nr_lmbs; i++) {
        uint64_t addr = i * lmb_size;
        uint32_t *dynamic_memory = cur_index;

        if (i >= hotplug_lmb_start) {
            sPAPRDRConnector *drc;

            drc = spapr_drc_by_id(TYPE_SPAPR_DRC_LMB, i);
            g_assert(drc);

            dynamic_memory[0] = cpu_to_be32(addr >> 32);
            dynamic_memory[1] = cpu_to_be32(addr & 0xffffffff);
            dynamic_memory[2] = cpu_to_be32(spapr_drc_index(drc));
            dynamic_memory[3] = cpu_to_be32(0); /* reserved */
            dynamic_memory[4] = cpu_to_be32(spapr_pc_dimm_node(dimms, addr));
            if (memory_region_present(get_system_memory(), addr)) {
                dynamic_memory[5] = cpu_to_be32(SPAPR_LMB_FLAGS_ASSIGNED);
            } else {
                dynamic_memory[5] = cpu_to_be32(0);
            }
        } else {
            /*
             * LMB information for RMA, boot time RAM and gap b/n RAM and
             * hotplug memory region -- all these are marked as reserved
             * and as having no valid DRC.
             */
            dynamic_memory[0] = cpu_to_be32(addr >> 32);
            dynamic_memory[1] = cpu_to_be32(addr & 0xffffffff);
            dynamic_memory[2] = cpu_to_be32(0);
            dynamic_memory[3] = cpu_to_be32(0); /* reserved */
            dynamic_memory[4] = cpu_to_be32(-1);
            dynamic_memory[5] = cpu_to_be32(SPAPR_LMB_FLAGS_RESERVED |
                                            SPAPR_LMB_FLAGS_DRC_INVALID);
        }

        cur_index += SPAPR_DR_LMB_LIST_ENTRY_SIZE;
    }
    qapi_free_MemoryDeviceInfoList(dimms);
    ret = fdt_setprop(fdt, offset, "ibm,dynamic-memory", int_buf, buf_len);
    if (ret < 0) {
        goto out;
    }

    /* ibm,associativity-lookup-arrays */
    cur_index = int_buf;
    int_buf[0] = cpu_to_be32(nr_nodes);
    int_buf[1] = cpu_to_be32(4); /* Number of entries per associativity list */
    cur_index += 2;
    for (i = 0; i < nr_nodes; i++) {
        uint32_t associativity[] = {
            cpu_to_be32(0x0),
            cpu_to_be32(0x0),
            cpu_to_be32(0x0),
            cpu_to_be32(i)
        };
        memcpy(cur_index, associativity, sizeof(associativity));
        cur_index += 4;
    }
    ret = fdt_setprop(fdt, offset, "ibm,associativity-lookup-arrays", int_buf,
            (cur_index - int_buf) * sizeof(uint32_t));
out:
    g_free(int_buf);
    return ret;
}

static int spapr_dt_cas_updates(sPAPRMachineState *spapr, void *fdt,
                                sPAPROptionVector *ov5_updates)
{
    sPAPRMachineClass *smc = SPAPR_MACHINE_GET_CLASS(spapr);
    int ret = 0, offset;

    /* Generate ibm,dynamic-reconfiguration-memory node if required */
    if (spapr_ovec_test(ov5_updates, OV5_DRCONF_MEMORY)) {
        g_assert(smc->dr_lmb_enabled);
        ret = spapr_populate_drconf_memory(spapr, fdt);
        if (ret) {
            goto out;
        }
    }

    offset = fdt_path_offset(fdt, "/chosen");
    if (offset < 0) {
        offset = fdt_add_subnode(fdt, 0, "chosen");
        if (offset < 0) {
            return offset;
        }
    }
    ret = spapr_ovec_populate_dt(fdt, offset, spapr->ov5_cas,
                                 "ibm,architecture-vec-5");

out:
    return ret;
}

static bool spapr_hotplugged_dev_before_cas(void)
{
    Object *drc_container, *obj;
    ObjectProperty *prop;
    ObjectPropertyIterator iter;

    drc_container = container_get(object_get_root(), "/dr-connector");
    object_property_iter_init(&iter, drc_container);
    while ((prop = object_property_iter_next(&iter))) {
        if (!strstart(prop->type, "link<", NULL)) {
            continue;
        }
        obj = object_property_get_link(drc_container, prop->name, NULL);
        if (spapr_drc_needed(obj)) {
            return true;
        }
    }
    return false;
}

int spapr_h_cas_compose_response(sPAPRMachineState *spapr,
                                 target_ulong addr, target_ulong size,
                                 sPAPROptionVector *ov5_updates)
{
    void *fdt, *fdt_skel;
    sPAPRDeviceTreeUpdateHeader hdr = { .version_id = 1 };

    if (spapr_hotplugged_dev_before_cas()) {
        return 1;
    }

    if (size < sizeof(hdr) || size > FW_MAX_SIZE) {
        error_report("SLOF provided an unexpected CAS buffer size "
                     TARGET_FMT_lu " (min: %zu, max: %u)",
                     size, sizeof(hdr), FW_MAX_SIZE);
        exit(EXIT_FAILURE);
    }

    size -= sizeof(hdr);

    /* Create skeleton */
    fdt_skel = g_malloc0(size);
    _FDT((fdt_create(fdt_skel, size)));
    _FDT((fdt_begin_node(fdt_skel, "")));
    _FDT((fdt_end_node(fdt_skel)));
    _FDT((fdt_finish(fdt_skel)));
    fdt = g_malloc0(size);
    _FDT((fdt_open_into(fdt_skel, fdt, size)));
    g_free(fdt_skel);

    /* Fixup cpu nodes */
    _FDT((spapr_fixup_cpu_dt(fdt, spapr)));

    if (spapr_dt_cas_updates(spapr, fdt, ov5_updates)) {
        return -1;
    }

    /* Pack resulting tree */
    _FDT((fdt_pack(fdt)));

    if (fdt_totalsize(fdt) + sizeof(hdr) > size) {
        trace_spapr_cas_failed(size);
        return -1;
    }

    cpu_physical_memory_write(addr, &hdr, sizeof(hdr));
    cpu_physical_memory_write(addr + sizeof(hdr), fdt, fdt_totalsize(fdt));
    trace_spapr_cas_continue(fdt_totalsize(fdt) + sizeof(hdr));
    g_free(fdt);

    return 0;
}

static void spapr_dt_rtas(sPAPRMachineState *spapr, void *fdt)
{
    int rtas;
    GString *hypertas = g_string_sized_new(256);
    GString *qemu_hypertas = g_string_sized_new(256);
    uint32_t refpoints[] = { cpu_to_be32(0x4), cpu_to_be32(0x4) };
    uint64_t max_hotplug_addr = spapr->hotplug_memory.base +
        memory_region_size(&spapr->hotplug_memory.mr);
    uint32_t lrdr_capacity[] = {
        cpu_to_be32(max_hotplug_addr >> 32),
        cpu_to_be32(max_hotplug_addr & 0xffffffff),
        0, cpu_to_be32(SPAPR_MEMORY_BLOCK_SIZE),
        cpu_to_be32(max_cpus / smp_threads),
    };

    _FDT(rtas = fdt_add_subnode(fdt, 0, "rtas"));

    /* hypertas */
    add_str(hypertas, "hcall-pft");
    add_str(hypertas, "hcall-term");
    add_str(hypertas, "hcall-dabr");
    add_str(hypertas, "hcall-interrupt");
    add_str(hypertas, "hcall-tce");
    add_str(hypertas, "hcall-vio");
    add_str(hypertas, "hcall-splpar");
    add_str(hypertas, "hcall-bulk");
    add_str(hypertas, "hcall-set-mode");
    add_str(hypertas, "hcall-sprg0");
    add_str(hypertas, "hcall-copy");
    add_str(hypertas, "hcall-debug");
    add_str(qemu_hypertas, "hcall-memop1");

    if (!kvm_enabled() || kvmppc_spapr_use_multitce()) {
        add_str(hypertas, "hcall-multi-tce");
    }

    if (spapr->resize_hpt != SPAPR_RESIZE_HPT_DISABLED) {
        add_str(hypertas, "hcall-hpt-resize");
    }

    _FDT(fdt_setprop(fdt, rtas, "ibm,hypertas-functions",
                     hypertas->str, hypertas->len));
    g_string_free(hypertas, TRUE);
    _FDT(fdt_setprop(fdt, rtas, "qemu,hypertas-functions",
                     qemu_hypertas->str, qemu_hypertas->len));
    g_string_free(qemu_hypertas, TRUE);

    _FDT(fdt_setprop(fdt, rtas, "ibm,associativity-reference-points",
                     refpoints, sizeof(refpoints)));

    _FDT(fdt_setprop_cell(fdt, rtas, "rtas-error-log-max",
                          RTAS_ERROR_LOG_MAX));
    _FDT(fdt_setprop_cell(fdt, rtas, "rtas-event-scan-rate",
                          RTAS_EVENT_SCAN_RATE));

    g_assert(msi_nonbroken);
    _FDT(fdt_setprop(fdt, rtas, "ibm,change-msix-capable", NULL, 0));

    /*
     * According to PAPR, rtas ibm,os-term does not guarantee a return
     * back to the guest cpu.
     *
     * While an additional ibm,extended-os-term property indicates
     * that rtas call return will always occur. Set this property.
     */
    _FDT(fdt_setprop(fdt, rtas, "ibm,extended-os-term", NULL, 0));

    _FDT(fdt_setprop(fdt, rtas, "ibm,lrdr-capacity",
                     lrdr_capacity, sizeof(lrdr_capacity)));

    spapr_dt_rtas_tokens(fdt, rtas);
}

/* Prepare ibm,arch-vec-5-platform-support, which indicates the MMU features
 * that the guest may request and thus the valid values for bytes 24..26 of
 * option vector 5: */
static void spapr_dt_ov5_platform_support(void *fdt, int chosen)
{
    PowerPCCPU *first_ppc_cpu = POWERPC_CPU(first_cpu);

    char val[2 * 4] = {
        23, 0x00, /* Xive mode, filled in below. */
        24, 0x00, /* Hash/Radix, filled in below. */
        25, 0x00, /* Hash options: Segment Tables == no, GTSE == no. */
        26, 0x40, /* Radix options: GTSE == yes. */
    };

    if (!ppc_check_compat(first_ppc_cpu, CPU_POWERPC_LOGICAL_3_00, 0,
                          first_ppc_cpu->compat_pvr)) {
        /* If we're in a pre POWER9 compat mode then the guest should do hash */
        val[3] = 0x00; /* Hash */
    } else if (kvm_enabled()) {
        if (kvmppc_has_cap_mmu_radix() && kvmppc_has_cap_mmu_hash_v3()) {
            val[3] = 0x80; /* OV5_MMU_BOTH */
        } else if (kvmppc_has_cap_mmu_radix()) {
            val[3] = 0x40; /* OV5_MMU_RADIX_300 */
        } else {
            val[3] = 0x00; /* Hash */
        }
    } else {
        /* V3 MMU supports both hash and radix in tcg (with dynamic switching) */
        val[3] = 0xC0;
    }
    _FDT(fdt_setprop(fdt, chosen, "ibm,arch-vec-5-platform-support",
                     val, sizeof(val)));
}

static void spapr_dt_chosen(sPAPRMachineState *spapr, void *fdt)
{
    MachineState *machine = MACHINE(spapr);
    int chosen;
    const char *boot_device = machine->boot_order;
    char *stdout_path = spapr_vio_stdout_path(spapr->vio_bus);
    size_t cb = 0;
    char *bootlist = get_boot_devices_list(&cb, true);

    _FDT(chosen = fdt_add_subnode(fdt, 0, "chosen"));

    _FDT(fdt_setprop_string(fdt, chosen, "bootargs", machine->kernel_cmdline));
    _FDT(fdt_setprop_cell(fdt, chosen, "linux,initrd-start",
                          spapr->initrd_base));
    _FDT(fdt_setprop_cell(fdt, chosen, "linux,initrd-end",
                          spapr->initrd_base + spapr->initrd_size));

    if (spapr->kernel_size) {
        uint64_t kprop[2] = { cpu_to_be64(KERNEL_LOAD_ADDR),
                              cpu_to_be64(spapr->kernel_size) };

        _FDT(fdt_setprop(fdt, chosen, "qemu,boot-kernel",
                         &kprop, sizeof(kprop)));
        if (spapr->kernel_le) {
            _FDT(fdt_setprop(fdt, chosen, "qemu,boot-kernel-le", NULL, 0));
        }
    }
    if (boot_menu) {
        _FDT((fdt_setprop_cell(fdt, chosen, "qemu,boot-menu", boot_menu)));
    }
    _FDT(fdt_setprop_cell(fdt, chosen, "qemu,graphic-width", graphic_width));
    _FDT(fdt_setprop_cell(fdt, chosen, "qemu,graphic-height", graphic_height));
    _FDT(fdt_setprop_cell(fdt, chosen, "qemu,graphic-depth", graphic_depth));

    if (cb && bootlist) {
        int i;

        for (i = 0; i < cb; i++) {
            if (bootlist[i] == '\n') {
                bootlist[i] = ' ';
            }
        }
        _FDT(fdt_setprop_string(fdt, chosen, "qemu,boot-list", bootlist));
    }

    if (boot_device && strlen(boot_device)) {
        _FDT(fdt_setprop_string(fdt, chosen, "qemu,boot-device", boot_device));
    }

    if (!spapr->has_graphics && stdout_path) {
        _FDT(fdt_setprop_string(fdt, chosen, "linux,stdout-path", stdout_path));
    }

    spapr_dt_ov5_platform_support(fdt, chosen);

    g_free(stdout_path);
    g_free(bootlist);
}

static void spapr_dt_hypervisor(sPAPRMachineState *spapr, void *fdt)
{
    /* The /hypervisor node isn't in PAPR - this is a hack to allow PR
     * KVM to work under pHyp with some guest co-operation */
    int hypervisor;
    uint8_t hypercall[16];

    _FDT(hypervisor = fdt_add_subnode(fdt, 0, "hypervisor"));
    /* indicate KVM hypercall interface */
    _FDT(fdt_setprop_string(fdt, hypervisor, "compatible", "linux,kvm"));
    if (kvmppc_has_cap_fixup_hcalls()) {
        /*
         * Older KVM versions with older guest kernels were broken
         * with the magic page, don't allow the guest to map it.
         */
        if (!kvmppc_get_hypercall(first_cpu->env_ptr, hypercall,
                                  sizeof(hypercall))) {
            _FDT(fdt_setprop(fdt, hypervisor, "hcall-instructions",
                             hypercall, sizeof(hypercall)));
        }
    }
}

static void *spapr_build_fdt(sPAPRMachineState *spapr,
                             hwaddr rtas_addr,
                             hwaddr rtas_size)
{
    MachineState *machine = MACHINE(spapr);
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    sPAPRMachineClass *smc = SPAPR_MACHINE_GET_CLASS(machine);
    int ret;
    void *fdt;
    sPAPRPHBState *phb;
    char *buf;

    fdt = g_malloc0(FDT_MAX_SIZE);
    _FDT((fdt_create_empty_tree(fdt, FDT_MAX_SIZE)));

    /* Root node */
    _FDT(fdt_setprop_string(fdt, 0, "device_type", "chrp"));
    _FDT(fdt_setprop_string(fdt, 0, "model", "IBM pSeries (emulated by qemu)"));
    _FDT(fdt_setprop_string(fdt, 0, "compatible", "qemu,pseries"));

    /*
     * Add info to guest to indentify which host is it being run on
     * and what is the uuid of the guest
     */
    if (kvmppc_get_host_model(&buf)) {
        _FDT(fdt_setprop_string(fdt, 0, "host-model", buf));
        g_free(buf);
    }
    if (kvmppc_get_host_serial(&buf)) {
        _FDT(fdt_setprop_string(fdt, 0, "host-serial", buf));
        g_free(buf);
    }

    buf = qemu_uuid_unparse_strdup(&qemu_uuid);

    _FDT(fdt_setprop_string(fdt, 0, "vm,uuid", buf));
    if (qemu_uuid_set) {
        _FDT(fdt_setprop_string(fdt, 0, "system-id", buf));
    }
    g_free(buf);

    if (qemu_get_vm_name()) {
        _FDT(fdt_setprop_string(fdt, 0, "ibm,partition-name",
                                qemu_get_vm_name()));
    }

    _FDT(fdt_setprop_cell(fdt, 0, "#address-cells", 2));
    _FDT(fdt_setprop_cell(fdt, 0, "#size-cells", 2));

    /* /interrupt controller */
    spapr_dt_xics(xics_max_server_number(spapr), fdt, PHANDLE_XICP);

    ret = spapr_populate_memory(spapr, fdt);
    if (ret < 0) {
        error_report("couldn't setup memory nodes in fdt");
        exit(1);
    }

    /* /vdevice */
    spapr_dt_vdevice(spapr->vio_bus, fdt);

    if (object_resolve_path_type("", TYPE_SPAPR_RNG, NULL)) {
        ret = spapr_rng_populate_dt(fdt);
        if (ret < 0) {
            error_report("could not set up rng device in the fdt");
            exit(1);
        }
    }

    QLIST_FOREACH(phb, &spapr->phbs, list) {
        ret = spapr_populate_pci_dt(phb, PHANDLE_XICP, fdt);
        if (ret < 0) {
            error_report("couldn't setup PCI devices in fdt");
            exit(1);
        }
    }

    /* cpus */
    spapr_populate_cpus_dt_node(fdt, spapr);

    if (smc->dr_lmb_enabled) {
        _FDT(spapr_drc_populate_dt(fdt, 0, NULL, SPAPR_DR_CONNECTOR_TYPE_LMB));
    }

    if (mc->has_hotpluggable_cpus) {
        int offset = fdt_path_offset(fdt, "/cpus");
        ret = spapr_drc_populate_dt(fdt, offset, NULL,
                                    SPAPR_DR_CONNECTOR_TYPE_CPU);
        if (ret < 0) {
            error_report("Couldn't set up CPU DR device tree properties");
            exit(1);
        }
    }

    /* /event-sources */
    spapr_dt_events(spapr, fdt);

    /* /rtas */
    spapr_dt_rtas(spapr, fdt);

    /* /chosen */
    spapr_dt_chosen(spapr, fdt);

    /* /hypervisor */
    if (kvm_enabled()) {
        spapr_dt_hypervisor(spapr, fdt);
    }

    /* Build memory reserve map */
    if (spapr->kernel_size) {
        _FDT((fdt_add_mem_rsv(fdt, KERNEL_LOAD_ADDR, spapr->kernel_size)));
    }
    if (spapr->initrd_size) {
        _FDT((fdt_add_mem_rsv(fdt, spapr->initrd_base, spapr->initrd_size)));
    }

    /* ibm,client-architecture-support updates */
    ret = spapr_dt_cas_updates(spapr, fdt, spapr->ov5_cas);
    if (ret < 0) {
        error_report("couldn't setup CAS properties fdt");
        exit(1);
    }

    return fdt;
}

static uint64_t translate_kernel_address(void *opaque, uint64_t addr)
{
    return (addr & 0x0fffffff) + KERNEL_LOAD_ADDR;
}

static void emulate_spapr_hypercall(PPCVirtualHypervisor *vhyp,
                                    PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;

    /* The TCG path should also be holding the BQL at this point */
    g_assert(qemu_mutex_iothread_locked());

    if (msr_pr) {
        hcall_dprintf("Hypercall made with MSR[PR]=1\n");
        env->gpr[3] = H_PRIVILEGE;
    } else {
        env->gpr[3] = spapr_hypercall(cpu, env->gpr[3], &env->gpr[4]);
    }
}

static uint64_t spapr_get_patbe(PPCVirtualHypervisor *vhyp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(vhyp);

    return spapr->patb_entry;
}

#define HPTE(_table, _i)   (void *)(((uint64_t *)(_table)) + ((_i) * 2))
#define HPTE_VALID(_hpte)  (tswap64(*((uint64_t *)(_hpte))) & HPTE64_V_VALID)
#define HPTE_DIRTY(_hpte)  (tswap64(*((uint64_t *)(_hpte))) & HPTE64_V_HPTE_DIRTY)
#define CLEAN_HPTE(_hpte)  ((*(uint64_t *)(_hpte)) &= tswap64(~HPTE64_V_HPTE_DIRTY))
#define DIRTY_HPTE(_hpte)  ((*(uint64_t *)(_hpte)) |= tswap64(HPTE64_V_HPTE_DIRTY))

/*
 * Get the fd to access the kernel htab, re-opening it if necessary
 */
static int get_htab_fd(sPAPRMachineState *spapr)
{
    Error *local_err = NULL;

    if (spapr->htab_fd >= 0) {
        return spapr->htab_fd;
    }

    spapr->htab_fd = kvmppc_get_htab_fd(false, 0, &local_err);
    if (spapr->htab_fd < 0) {
        error_report_err(local_err);
    }

    return spapr->htab_fd;
}

void close_htab_fd(sPAPRMachineState *spapr)
{
    if (spapr->htab_fd >= 0) {
        close(spapr->htab_fd);
    }
    spapr->htab_fd = -1;
}

static hwaddr spapr_hpt_mask(PPCVirtualHypervisor *vhyp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(vhyp);

    return HTAB_SIZE(spapr) / HASH_PTEG_SIZE_64 - 1;
}

static target_ulong spapr_encode_hpt_for_kvm_pr(PPCVirtualHypervisor *vhyp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(vhyp);

    assert(kvm_enabled());

    if (!spapr->htab) {
        return 0;
    }

    return (target_ulong)(uintptr_t)spapr->htab | (spapr->htab_shift - 18);
}

static const ppc_hash_pte64_t *spapr_map_hptes(PPCVirtualHypervisor *vhyp,
                                                hwaddr ptex, int n)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(vhyp);
    hwaddr pte_offset = ptex * HASH_PTE_SIZE_64;

    if (!spapr->htab) {
        /*
         * HTAB is controlled by KVM. Fetch into temporary buffer
         */
        ppc_hash_pte64_t *hptes = g_malloc(n * HASH_PTE_SIZE_64);
        kvmppc_read_hptes(hptes, ptex, n);
        return hptes;
    }

    /*
     * HTAB is controlled by QEMU. Just point to the internally
     * accessible PTEG.
     */
    return (const ppc_hash_pte64_t *)(spapr->htab + pte_offset);
}

static void spapr_unmap_hptes(PPCVirtualHypervisor *vhyp,
                              const ppc_hash_pte64_t *hptes,
                              hwaddr ptex, int n)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(vhyp);

    if (!spapr->htab) {
        g_free((void *)hptes);
    }

    /* Nothing to do for qemu managed HPT */
}

static void spapr_store_hpte(PPCVirtualHypervisor *vhyp, hwaddr ptex,
                             uint64_t pte0, uint64_t pte1)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(vhyp);
    hwaddr offset = ptex * HASH_PTE_SIZE_64;

    if (!spapr->htab) {
        kvmppc_write_hpte(ptex, pte0, pte1);
    } else {
        stq_p(spapr->htab + offset, pte0);
        stq_p(spapr->htab + offset + HASH_PTE_SIZE_64 / 2, pte1);
    }
}

int spapr_hpt_shift_for_ramsize(uint64_t ramsize)
{
    int shift;

    /* We aim for a hash table of size 1/128 the size of RAM (rounded
     * up).  The PAPR recommendation is actually 1/64 of RAM size, but
     * that's much more than is needed for Linux guests */
    shift = ctz64(pow2ceil(ramsize)) - 7;
    shift = MAX(shift, 18); /* Minimum architected size */
    shift = MIN(shift, 46); /* Maximum architected size */
    return shift;
}

void spapr_free_hpt(sPAPRMachineState *spapr)
{
    g_free(spapr->htab);
    spapr->htab = NULL;
    spapr->htab_shift = 0;
    close_htab_fd(spapr);
}

void spapr_reallocate_hpt(sPAPRMachineState *spapr, int shift,
                          Error **errp)
{
    long rc;

    /* Clean up any HPT info from a previous boot */
    spapr_free_hpt(spapr);

    rc = kvmppc_reset_htab(shift);
    if (rc < 0) {
        /* kernel-side HPT needed, but couldn't allocate one */
        error_setg_errno(errp, errno,
                         "Failed to allocate KVM HPT of order %d (try smaller maxmem?)",
                         shift);
        /* This is almost certainly fatal, but if the caller really
         * wants to carry on with shift == 0, it's welcome to try */
    } else if (rc > 0) {
        /* kernel-side HPT allocated */
        if (rc != shift) {
            error_setg(errp,
                       "Requested order %d HPT, but kernel allocated order %ld (try smaller maxmem?)",
                       shift, rc);
        }

        spapr->htab_shift = shift;
        spapr->htab = NULL;
    } else {
        /* kernel-side HPT not needed, allocate in userspace instead */
        size_t size = 1ULL << shift;
        int i;

        spapr->htab = qemu_memalign(size, size);
        if (!spapr->htab) {
            error_setg_errno(errp, errno,
                             "Could not allocate HPT of order %d", shift);
            return;
        }

        memset(spapr->htab, 0, size);
        spapr->htab_shift = shift;

        for (i = 0; i < size / HASH_PTE_SIZE_64; i++) {
            DIRTY_HPTE(HPTE(spapr->htab, i));
        }
    }
    /* We're setting up a hash table, so that means we're not radix */
    spapr->patb_entry = 0;
}

void spapr_setup_hpt_and_vrma(sPAPRMachineState *spapr)
{
    int hpt_shift;

    if ((spapr->resize_hpt == SPAPR_RESIZE_HPT_DISABLED)
        || (spapr->cas_reboot
            && !spapr_ovec_test(spapr->ov5_cas, OV5_HPT_RESIZE))) {
        hpt_shift = spapr_hpt_shift_for_ramsize(MACHINE(spapr)->maxram_size);
    } else {
        uint64_t current_ram_size;

        current_ram_size = MACHINE(spapr)->ram_size + get_plugged_memory_size();
        hpt_shift = spapr_hpt_shift_for_ramsize(current_ram_size);
    }
    spapr_reallocate_hpt(spapr, hpt_shift, &error_fatal);

    if (spapr->vrma_adjust) {
        spapr->rma_size = kvmppc_rma_size(spapr_node0_size(MACHINE(spapr)),
                                          spapr->htab_shift);
    }
}

static void find_unknown_sysbus_device(SysBusDevice *sbdev, void *opaque)
{
    bool matched = false;

    if (object_dynamic_cast(OBJECT(sbdev), TYPE_SPAPR_PCI_HOST_BRIDGE)) {
        matched = true;
    }

    if (!matched) {
        error_report("Device %s is not supported by this machine yet.",
                     qdev_fw_name(DEVICE(sbdev)));
        exit(1);
    }
}

static int spapr_reset_drcs(Object *child, void *opaque)
{
    sPAPRDRConnector *drc =
        (sPAPRDRConnector *) object_dynamic_cast(child,
                                                 TYPE_SPAPR_DR_CONNECTOR);

    if (drc) {
        spapr_drc_reset(drc);
    }

    return 0;
}

static void spapr_machine_reset(void)
{
    MachineState *machine = MACHINE(qdev_get_machine());
    sPAPRMachineState *spapr = SPAPR_MACHINE(machine);
    PowerPCCPU *first_ppc_cpu;
    uint32_t rtas_limit;
    hwaddr rtas_addr, fdt_addr;
    void *fdt;
    int rc;

    /* Check for unknown sysbus devices */
    foreach_dynamic_sysbus_device(find_unknown_sysbus_device, NULL);

    spapr_caps_reset(spapr);

    first_ppc_cpu = POWERPC_CPU(first_cpu);
    if (kvm_enabled() && kvmppc_has_cap_mmu_radix() &&
        ppc_check_compat(first_ppc_cpu, CPU_POWERPC_LOGICAL_3_00, 0,
                         spapr->max_compat_pvr)) {
        /* If using KVM with radix mode available, VCPUs can be started
         * without a HPT because KVM will start them in radix mode.
         * Set the GR bit in PATB so that we know there is no HPT. */
        spapr->patb_entry = PATBE1_GR;
    } else {
        spapr_setup_hpt_and_vrma(spapr);
    }

    /* if this reset wasn't generated by CAS, we should reset our
     * negotiated options and start from scratch */
    if (!spapr->cas_reboot) {
        spapr_ovec_cleanup(spapr->ov5_cas);
        spapr->ov5_cas = spapr_ovec_new();

        ppc_set_compat(first_ppc_cpu, spapr->max_compat_pvr, &error_fatal);
    }

    qemu_devices_reset();

    /* DRC reset may cause a device to be unplugged. This will cause troubles
     * if this device is used by another device (eg, a running vhost backend
     * will crash QEMU if the DIMM holding the vring goes away). To avoid such
     * situations, we reset DRCs after all devices have been reset.
     */
    object_child_foreach_recursive(object_get_root(), spapr_reset_drcs, NULL);

    spapr_clear_pending_events(spapr);

    /*
     * We place the device tree and RTAS just below either the top of the RMA,
     * or just below 2GB, whichever is lowere, so that it can be
     * processed with 32-bit real mode code if necessary
     */
    rtas_limit = MIN(spapr->rma_size, RTAS_MAX_ADDR);
    rtas_addr = rtas_limit - RTAS_MAX_SIZE;
    fdt_addr = rtas_addr - FDT_MAX_SIZE;

    fdt = spapr_build_fdt(spapr, rtas_addr, spapr->rtas_size);

    spapr_load_rtas(spapr, fdt, rtas_addr);

    rc = fdt_pack(fdt);

    /* Should only fail if we've built a corrupted tree */
    assert(rc == 0);

    if (fdt_totalsize(fdt) > FDT_MAX_SIZE) {
        error_report("FDT too big ! 0x%x bytes (max is 0x%x)",
                     fdt_totalsize(fdt), FDT_MAX_SIZE);
        exit(1);
    }

    /* Load the fdt */
    qemu_fdt_dumpdtb(fdt, fdt_totalsize(fdt));
    cpu_physical_memory_write(fdt_addr, fdt, fdt_totalsize(fdt));
    g_free(fdt);

    /* Set up the entry state */
    first_ppc_cpu->env.gpr[3] = fdt_addr;
    first_ppc_cpu->env.gpr[5] = 0;
    first_cpu->halted = 0;
    first_ppc_cpu->env.nip = SPAPR_ENTRY_POINT;

    spapr->cas_reboot = false;
}

static void spapr_create_nvram(sPAPRMachineState *spapr)
{
    DeviceState *dev = qdev_create(&spapr->vio_bus->bus, "spapr-nvram");
    DriveInfo *dinfo = drive_get(IF_PFLASH, 0, 0);

    if (dinfo) {
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo),
                            &error_fatal);
    }

    qdev_init_nofail(dev);

    spapr->nvram = (struct sPAPRNVRAM *)dev;
}

static void spapr_rtc_create(sPAPRMachineState *spapr)
{
    object_initialize(&spapr->rtc, sizeof(spapr->rtc), TYPE_SPAPR_RTC);
    object_property_add_child(OBJECT(spapr), "rtc", OBJECT(&spapr->rtc),
                              &error_fatal);
    object_property_set_bool(OBJECT(&spapr->rtc), true, "realized",
                              &error_fatal);
    object_property_add_alias(OBJECT(spapr), "rtc-time", OBJECT(&spapr->rtc),
                              "date", &error_fatal);
}

/* Returns whether we want to use VGA or not */
static bool spapr_vga_init(PCIBus *pci_bus, Error **errp)
{
    switch (vga_interface_type) {
    case VGA_NONE:
        return false;
    case VGA_DEVICE:
        return true;
    case VGA_STD:
    case VGA_VIRTIO:
        return pci_vga_init(pci_bus) != NULL;
    default:
        error_setg(errp,
                   "Unsupported VGA mode, only -vga std or -vga virtio is supported");
        return false;
    }
}

static int spapr_pre_load(void *opaque)
{
    int rc;

    rc = spapr_caps_pre_load(opaque);
    if (rc) {
        return rc;
    }

    return 0;
}

static int spapr_post_load(void *opaque, int version_id)
{
    sPAPRMachineState *spapr = (sPAPRMachineState *)opaque;
    int err = 0;

    err = spapr_caps_post_migration(spapr);
    if (err) {
        return err;
    }

    if (!object_dynamic_cast(OBJECT(spapr->ics), TYPE_ICS_KVM)) {
        CPUState *cs;
        CPU_FOREACH(cs) {
            PowerPCCPU *cpu = POWERPC_CPU(cs);
            icp_resend(ICP(cpu->intc));
        }
    }

    /* In earlier versions, there was no separate qdev for the PAPR
     * RTC, so the RTC offset was stored directly in sPAPREnvironment.
     * So when migrating from those versions, poke the incoming offset
     * value into the RTC device */
    if (version_id < 3) {
        err = spapr_rtc_import_offset(&spapr->rtc, spapr->rtc_offset);
    }

    if (kvm_enabled() && spapr->patb_entry) {
        PowerPCCPU *cpu = POWERPC_CPU(first_cpu);
        bool radix = !!(spapr->patb_entry & PATBE1_GR);
        bool gtse = !!(cpu->env.spr[SPR_LPCR] & LPCR_GTSE);

        err = kvmppc_configure_v3_mmu(cpu, radix, gtse, spapr->patb_entry);
        if (err) {
            error_report("Process table config unsupported by the host");
            return -EINVAL;
        }
    }

    return err;
}

static int spapr_pre_save(void *opaque)
{
    int rc;

    rc = spapr_caps_pre_save(opaque);
    if (rc) {
        return rc;
    }

    return 0;
}

static bool version_before_3(void *opaque, int version_id)
{
    return version_id < 3;
}

static bool spapr_pending_events_needed(void *opaque)
{
    sPAPRMachineState *spapr = (sPAPRMachineState *)opaque;
    return !QTAILQ_EMPTY(&spapr->pending_events);
}

static const VMStateDescription vmstate_spapr_event_entry = {
    .name = "spapr_event_log_entry",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(summary, sPAPREventLogEntry),
        VMSTATE_UINT32(extended_length, sPAPREventLogEntry),
        VMSTATE_VBUFFER_ALLOC_UINT32(extended_log, sPAPREventLogEntry, 0,
                                     NULL, extended_length),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_spapr_pending_events = {
    .name = "spapr_pending_events",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = spapr_pending_events_needed,
    .fields = (VMStateField[]) {
        VMSTATE_QTAILQ_V(pending_events, sPAPRMachineState, 1,
                         vmstate_spapr_event_entry, sPAPREventLogEntry, next),
        VMSTATE_END_OF_LIST()
    },
};

static bool spapr_ov5_cas_needed(void *opaque)
{
    sPAPRMachineState *spapr = opaque;
    sPAPROptionVector *ov5_mask = spapr_ovec_new();
    sPAPROptionVector *ov5_legacy = spapr_ovec_new();
    sPAPROptionVector *ov5_removed = spapr_ovec_new();
    bool cas_needed;

    /* Prior to the introduction of sPAPROptionVector, we had two option
     * vectors we dealt with: OV5_FORM1_AFFINITY, and OV5_DRCONF_MEMORY.
     * Both of these options encode machine topology into the device-tree
     * in such a way that the now-booted OS should still be able to interact
     * appropriately with QEMU regardless of what options were actually
     * negotiatied on the source side.
     *
     * As such, we can avoid migrating the CAS-negotiated options if these
     * are the only options available on the current machine/platform.
     * Since these are the only options available for pseries-2.7 and
     * earlier, this allows us to maintain old->new/new->old migration
     * compatibility.
     *
     * For QEMU 2.8+, there are additional CAS-negotiatable options available
     * via default pseries-2.8 machines and explicit command-line parameters.
     * Some of these options, like OV5_HP_EVT, *do* require QEMU to be aware
     * of the actual CAS-negotiated values to continue working properly. For
     * example, availability of memory unplug depends on knowing whether
     * OV5_HP_EVT was negotiated via CAS.
     *
     * Thus, for any cases where the set of available CAS-negotiatable
     * options extends beyond OV5_FORM1_AFFINITY and OV5_DRCONF_MEMORY, we
     * include the CAS-negotiated options in the migration stream.
     */
    spapr_ovec_set(ov5_mask, OV5_FORM1_AFFINITY);
    spapr_ovec_set(ov5_mask, OV5_DRCONF_MEMORY);

    /* spapr_ovec_diff returns true if bits were removed. we avoid using
     * the mask itself since in the future it's possible "legacy" bits may be
     * removed via machine options, which could generate a false positive
     * that breaks migration.
     */
    spapr_ovec_intersect(ov5_legacy, spapr->ov5, ov5_mask);
    cas_needed = spapr_ovec_diff(ov5_removed, spapr->ov5, ov5_legacy);

    spapr_ovec_cleanup(ov5_mask);
    spapr_ovec_cleanup(ov5_legacy);
    spapr_ovec_cleanup(ov5_removed);

    return cas_needed;
}

static const VMStateDescription vmstate_spapr_ov5_cas = {
    .name = "spapr_option_vector_ov5_cas",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = spapr_ov5_cas_needed,
    .fields = (VMStateField[]) {
        VMSTATE_STRUCT_POINTER_V(ov5_cas, sPAPRMachineState, 1,
                                 vmstate_spapr_ovec, sPAPROptionVector),
        VMSTATE_END_OF_LIST()
    },
};

static bool spapr_patb_entry_needed(void *opaque)
{
    sPAPRMachineState *spapr = opaque;

    return !!spapr->patb_entry;
}

static const VMStateDescription vmstate_spapr_patb_entry = {
    .name = "spapr_patb_entry",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = spapr_patb_entry_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(patb_entry, sPAPRMachineState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_spapr = {
    .name = "spapr",
    .version_id = 3,
    .minimum_version_id = 1,
    .pre_load = spapr_pre_load,
    .post_load = spapr_post_load,
    .pre_save = spapr_pre_save,
    .fields = (VMStateField[]) {
        /* used to be @next_irq */
        VMSTATE_UNUSED_BUFFER(version_before_3, 0, 4),

        /* RTC offset */
        VMSTATE_UINT64_TEST(rtc_offset, sPAPRMachineState, version_before_3),

        VMSTATE_PPC_TIMEBASE_V(tb, sPAPRMachineState, 2),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_spapr_ov5_cas,
        &vmstate_spapr_patb_entry,
        &vmstate_spapr_pending_events,
        &vmstate_spapr_cap_htm,
        &vmstate_spapr_cap_vsx,
        &vmstate_spapr_cap_dfp,
        &vmstate_spapr_cap_cfpc,
        &vmstate_spapr_cap_sbbc,
        &vmstate_spapr_cap_ibs,
        NULL
    }
};

static int htab_save_setup(QEMUFile *f, void *opaque)
{
    sPAPRMachineState *spapr = opaque;

    /* "Iteration" header */
    if (!spapr->htab_shift) {
        qemu_put_be32(f, -1);
    } else {
        qemu_put_be32(f, spapr->htab_shift);
    }

    if (spapr->htab) {
        spapr->htab_save_index = 0;
        spapr->htab_first_pass = true;
    } else {
        if (spapr->htab_shift) {
            assert(kvm_enabled());
        }
    }


    return 0;
}

static void htab_save_chunk(QEMUFile *f, sPAPRMachineState *spapr,
                            int chunkstart, int n_valid, int n_invalid)
{
    qemu_put_be32(f, chunkstart);
    qemu_put_be16(f, n_valid);
    qemu_put_be16(f, n_invalid);
    qemu_put_buffer(f, HPTE(spapr->htab, chunkstart),
                    HASH_PTE_SIZE_64 * n_valid);
}

static void htab_save_end_marker(QEMUFile *f)
{
    qemu_put_be32(f, 0);
    qemu_put_be16(f, 0);
    qemu_put_be16(f, 0);
}

static void htab_save_first_pass(QEMUFile *f, sPAPRMachineState *spapr,
                                 int64_t max_ns)
{
    bool has_timeout = max_ns != -1;
    int htabslots = HTAB_SIZE(spapr) / HASH_PTE_SIZE_64;
    int index = spapr->htab_save_index;
    int64_t starttime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    assert(spapr->htab_first_pass);

    do {
        int chunkstart;

        /* Consume invalid HPTEs */
        while ((index < htabslots)
               && !HPTE_VALID(HPTE(spapr->htab, index))) {
            CLEAN_HPTE(HPTE(spapr->htab, index));
            index++;
        }

        /* Consume valid HPTEs */
        chunkstart = index;
        while ((index < htabslots) && (index - chunkstart < USHRT_MAX)
               && HPTE_VALID(HPTE(spapr->htab, index))) {
            CLEAN_HPTE(HPTE(spapr->htab, index));
            index++;
        }

        if (index > chunkstart) {
            int n_valid = index - chunkstart;

            htab_save_chunk(f, spapr, chunkstart, n_valid, 0);

            if (has_timeout &&
                (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - starttime) > max_ns) {
                break;
            }
        }
    } while ((index < htabslots) && !qemu_file_rate_limit(f));

    if (index >= htabslots) {
        assert(index == htabslots);
        index = 0;
        spapr->htab_first_pass = false;
    }
    spapr->htab_save_index = index;
}

static int htab_save_later_pass(QEMUFile *f, sPAPRMachineState *spapr,
                                int64_t max_ns)
{
    bool final = max_ns < 0;
    int htabslots = HTAB_SIZE(spapr) / HASH_PTE_SIZE_64;
    int examined = 0, sent = 0;
    int index = spapr->htab_save_index;
    int64_t starttime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    assert(!spapr->htab_first_pass);

    do {
        int chunkstart, invalidstart;

        /* Consume non-dirty HPTEs */
        while ((index < htabslots)
               && !HPTE_DIRTY(HPTE(spapr->htab, index))) {
            index++;
            examined++;
        }

        chunkstart = index;
        /* Consume valid dirty HPTEs */
        while ((index < htabslots) && (index - chunkstart < USHRT_MAX)
               && HPTE_DIRTY(HPTE(spapr->htab, index))
               && HPTE_VALID(HPTE(spapr->htab, index))) {
            CLEAN_HPTE(HPTE(spapr->htab, index));
            index++;
            examined++;
        }

        invalidstart = index;
        /* Consume invalid dirty HPTEs */
        while ((index < htabslots) && (index - invalidstart < USHRT_MAX)
               && HPTE_DIRTY(HPTE(spapr->htab, index))
               && !HPTE_VALID(HPTE(spapr->htab, index))) {
            CLEAN_HPTE(HPTE(spapr->htab, index));
            index++;
            examined++;
        }

        if (index > chunkstart) {
            int n_valid = invalidstart - chunkstart;
            int n_invalid = index - invalidstart;

            htab_save_chunk(f, spapr, chunkstart, n_valid, n_invalid);
            sent += index - chunkstart;

            if (!final && (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - starttime) > max_ns) {
                break;
            }
        }

        if (examined >= htabslots) {
            break;
        }

        if (index >= htabslots) {
            assert(index == htabslots);
            index = 0;
        }
    } while ((examined < htabslots) && (!qemu_file_rate_limit(f) || final));

    if (index >= htabslots) {
        assert(index == htabslots);
        index = 0;
    }

    spapr->htab_save_index = index;

    return (examined >= htabslots) && (sent == 0) ? 1 : 0;
}

#define MAX_ITERATION_NS    5000000 /* 5 ms */
#define MAX_KVM_BUF_SIZE    2048

static int htab_save_iterate(QEMUFile *f, void *opaque)
{
    sPAPRMachineState *spapr = opaque;
    int fd;
    int rc = 0;

    /* Iteration header */
    if (!spapr->htab_shift) {
        qemu_put_be32(f, -1);
        return 1;
    } else {
        qemu_put_be32(f, 0);
    }

    if (!spapr->htab) {
        assert(kvm_enabled());

        fd = get_htab_fd(spapr);
        if (fd < 0) {
            return fd;
        }

        rc = kvmppc_save_htab(f, fd, MAX_KVM_BUF_SIZE, MAX_ITERATION_NS);
        if (rc < 0) {
            return rc;
        }
    } else  if (spapr->htab_first_pass) {
        htab_save_first_pass(f, spapr, MAX_ITERATION_NS);
    } else {
        rc = htab_save_later_pass(f, spapr, MAX_ITERATION_NS);
    }

    htab_save_end_marker(f);

    return rc;
}

static int htab_save_complete(QEMUFile *f, void *opaque)
{
    sPAPRMachineState *spapr = opaque;
    int fd;

    /* Iteration header */
    if (!spapr->htab_shift) {
        qemu_put_be32(f, -1);
        return 0;
    } else {
        qemu_put_be32(f, 0);
    }

    if (!spapr->htab) {
        int rc;

        assert(kvm_enabled());

        fd = get_htab_fd(spapr);
        if (fd < 0) {
            return fd;
        }

        rc = kvmppc_save_htab(f, fd, MAX_KVM_BUF_SIZE, -1);
        if (rc < 0) {
            return rc;
        }
    } else {
        if (spapr->htab_first_pass) {
            htab_save_first_pass(f, spapr, -1);
        }
        htab_save_later_pass(f, spapr, -1);
    }

    /* End marker */
    htab_save_end_marker(f);

    return 0;
}

static int htab_load(QEMUFile *f, void *opaque, int version_id)
{
    sPAPRMachineState *spapr = opaque;
    uint32_t section_hdr;
    int fd = -1;
    Error *local_err = NULL;

    if (version_id < 1 || version_id > 1) {
        error_report("htab_load() bad version");
        return -EINVAL;
    }

    section_hdr = qemu_get_be32(f);

    if (section_hdr == -1) {
        spapr_free_hpt(spapr);
        return 0;
    }

    if (section_hdr) {
        /* First section gives the htab size */
        spapr_reallocate_hpt(spapr, section_hdr, &local_err);
        if (local_err) {
            error_report_err(local_err);
            return -EINVAL;
        }
        return 0;
    }

    if (!spapr->htab) {
        assert(kvm_enabled());

        fd = kvmppc_get_htab_fd(true, 0, &local_err);
        if (fd < 0) {
            error_report_err(local_err);
            return fd;
        }
    }

    while (true) {
        uint32_t index;
        uint16_t n_valid, n_invalid;

        index = qemu_get_be32(f);
        n_valid = qemu_get_be16(f);
        n_invalid = qemu_get_be16(f);

        if ((index == 0) && (n_valid == 0) && (n_invalid == 0)) {
            /* End of Stream */
            break;
        }

        if ((index + n_valid + n_invalid) >
            (HTAB_SIZE(spapr) / HASH_PTE_SIZE_64)) {
            /* Bad index in stream */
            error_report(
                "htab_load() bad index %d (%hd+%hd entries) in htab stream (htab_shift=%d)",
                index, n_valid, n_invalid, spapr->htab_shift);
            return -EINVAL;
        }

        if (spapr->htab) {
            if (n_valid) {
                qemu_get_buffer(f, HPTE(spapr->htab, index),
                                HASH_PTE_SIZE_64 * n_valid);
            }
            if (n_invalid) {
                memset(HPTE(spapr->htab, index + n_valid), 0,
                       HASH_PTE_SIZE_64 * n_invalid);
            }
        } else {
            int rc;

            assert(fd >= 0);

            rc = kvmppc_load_htab_chunk(f, fd, index, n_valid, n_invalid);
            if (rc < 0) {
                return rc;
            }
        }
    }

    if (!spapr->htab) {
        assert(fd >= 0);
        close(fd);
    }

    return 0;
}

static void htab_save_cleanup(void *opaque)
{
    sPAPRMachineState *spapr = opaque;

    close_htab_fd(spapr);
}

static SaveVMHandlers savevm_htab_handlers = {
    .save_setup = htab_save_setup,
    .save_live_iterate = htab_save_iterate,
    .save_live_complete_precopy = htab_save_complete,
    .save_cleanup = htab_save_cleanup,
    .load_state = htab_load,
};

static void spapr_boot_set(void *opaque, const char *boot_device,
                           Error **errp)
{
    MachineState *machine = MACHINE(opaque);
    machine->boot_order = g_strdup(boot_device);
}

static void spapr_create_lmb_dr_connectors(sPAPRMachineState *spapr)
{
    MachineState *machine = MACHINE(spapr);
    uint64_t lmb_size = SPAPR_MEMORY_BLOCK_SIZE;
    uint32_t nr_lmbs = (machine->maxram_size - machine->ram_size)/lmb_size;
    int i;

    for (i = 0; i < nr_lmbs; i++) {
        uint64_t addr;

        addr = i * lmb_size + spapr->hotplug_memory.base;
        spapr_dr_connector_new(OBJECT(spapr), TYPE_SPAPR_DRC_LMB,
                               addr / lmb_size);
    }
}

/*
 * If RAM size, maxmem size and individual node mem sizes aren't aligned
 * to SPAPR_MEMORY_BLOCK_SIZE(256MB), then refuse to start the guest
 * since we can't support such unaligned sizes with DRCONF_MEMORY.
 */
static void spapr_validate_node_memory(MachineState *machine, Error **errp)
{
    int i;

    if (machine->ram_size % SPAPR_MEMORY_BLOCK_SIZE) {
        error_setg(errp, "Memory size 0x" RAM_ADDR_FMT
                   " is not aligned to %llu MiB",
                   machine->ram_size,
                   SPAPR_MEMORY_BLOCK_SIZE / M_BYTE);
        return;
    }

    if (machine->maxram_size % SPAPR_MEMORY_BLOCK_SIZE) {
        error_setg(errp, "Maximum memory size 0x" RAM_ADDR_FMT
                   " is not aligned to %llu MiB",
                   machine->ram_size,
                   SPAPR_MEMORY_BLOCK_SIZE / M_BYTE);
        return;
    }

    for (i = 0; i < nb_numa_nodes; i++) {
        if (numa_info[i].node_mem % SPAPR_MEMORY_BLOCK_SIZE) {
            error_setg(errp,
                       "Node %d memory size 0x%" PRIx64
                       " is not aligned to %llu MiB",
                       i, numa_info[i].node_mem,
                       SPAPR_MEMORY_BLOCK_SIZE / M_BYTE);
            return;
        }
    }
}

/* find cpu slot in machine->possible_cpus by core_id */
static CPUArchId *spapr_find_cpu_slot(MachineState *ms, uint32_t id, int *idx)
{
    int index = id / smp_threads;

    if (index >= ms->possible_cpus->len) {
        return NULL;
    }
    if (idx) {
        *idx = index;
    }
    return &ms->possible_cpus->cpus[index];
}

static void spapr_init_cpus(sPAPRMachineState *spapr)
{
    MachineState *machine = MACHINE(spapr);
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    const char *type = spapr_get_cpu_core_type(machine->cpu_type);
    const CPUArchIdList *possible_cpus;
    int boot_cores_nr = smp_cpus / smp_threads;
    int i;

    possible_cpus = mc->possible_cpu_arch_ids(machine);
    if (mc->has_hotpluggable_cpus) {
        if (smp_cpus % smp_threads) {
            error_report("smp_cpus (%u) must be multiple of threads (%u)",
                         smp_cpus, smp_threads);
            exit(1);
        }
        if (max_cpus % smp_threads) {
            error_report("max_cpus (%u) must be multiple of threads (%u)",
                         max_cpus, smp_threads);
            exit(1);
        }
    } else {
        if (max_cpus != smp_cpus) {
            error_report("This machine version does not support CPU hotplug");
            exit(1);
        }
        boot_cores_nr = possible_cpus->len;
    }

    for (i = 0; i < possible_cpus->len; i++) {
        int core_id = i * smp_threads;

        if (mc->has_hotpluggable_cpus) {
            spapr_dr_connector_new(OBJECT(spapr), TYPE_SPAPR_DRC_CPU,
                                   spapr_vcpu_id(spapr, core_id));
        }

        if (i < boot_cores_nr) {
            Object *core  = object_new(type);
            int nr_threads = smp_threads;

            /* Handle the partially filled core for older machine types */
            if ((i + 1) * smp_threads >= smp_cpus) {
                nr_threads = smp_cpus - i * smp_threads;
            }

            object_property_set_int(core, nr_threads, "nr-threads",
                                    &error_fatal);
            object_property_set_int(core, core_id, CPU_CORE_PROP_CORE_ID,
                                    &error_fatal);
            object_property_set_bool(core, true, "realized", &error_fatal);
        }
    }
}

static void spapr_set_vsmt_mode(sPAPRMachineState *spapr, Error **errp)
{
    Error *local_err = NULL;
    bool vsmt_user = !!spapr->vsmt;
    int kvm_smt = kvmppc_smt_threads();
    int ret;

    if (!kvm_enabled() && (smp_threads > 1)) {
        error_setg(&local_err, "TCG cannot support more than 1 thread/core "
                     "on a pseries machine");
        goto out;
    }
    if (!is_power_of_2(smp_threads)) {
        error_setg(&local_err, "Cannot support %d threads/core on a pseries "
                     "machine because it must be a power of 2", smp_threads);
        goto out;
    }

    /* Detemine the VSMT mode to use: */
    if (vsmt_user) {
        if (spapr->vsmt < smp_threads) {
            error_setg(&local_err, "Cannot support VSMT mode %d"
                         " because it must be >= threads/core (%d)",
                         spapr->vsmt, smp_threads);
            goto out;
        }
        /* In this case, spapr->vsmt has been set by the command line */
    } else {
        /*
         * Default VSMT value is tricky, because we need it to be as
         * consistent as possible (for migration), but this requires
         * changing it for at least some existing cases.  We pick 8 as
         * the value that we'd get with KVM on POWER8, the
         * overwhelmingly common case in production systems.
         */
        spapr->vsmt = MAX(8, smp_threads);
    }

    /* KVM: If necessary, set the SMT mode: */
    if (kvm_enabled() && (spapr->vsmt != kvm_smt)) {
        ret = kvmppc_set_smt_threads(spapr->vsmt);
        if (ret) {
            /* Looks like KVM isn't able to change VSMT mode */
            error_setg(&local_err,
                       "Failed to set KVM's VSMT mode to %d (errno %d)",
                       spapr->vsmt, ret);
            /* We can live with that if the default one is big enough
             * for the number of threads, and a submultiple of the one
             * we want.  In this case we'll waste some vcpu ids, but
             * behaviour will be correct */
            if ((kvm_smt >= smp_threads) && ((spapr->vsmt % kvm_smt) == 0)) {
                warn_report_err(local_err);
                local_err = NULL;
                goto out;
            } else {
                if (!vsmt_user) {
                    error_append_hint(&local_err,
                                      "On PPC, a VM with %d threads/core"
                                      " on a host with %d threads/core"
                                      " requires the use of VSMT mode %d.\n",
                                      smp_threads, kvm_smt, spapr->vsmt);
                }
                kvmppc_hint_smt_possible(&local_err);
                goto out;
            }
        }
    }
    /* else TCG: nothing to do currently */
out:
    error_propagate(errp, local_err);
}

/* pSeries LPAR / sPAPR hardware init */
static void spapr_machine_init(MachineState *machine)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(machine);
    sPAPRMachineClass *smc = SPAPR_MACHINE_GET_CLASS(machine);
    const char *kernel_filename = machine->kernel_filename;
    const char *initrd_filename = machine->initrd_filename;
    PCIHostState *phb;
    int i;
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    MemoryRegion *rma_region;
    void *rma = NULL;
    hwaddr rma_alloc_size;
    hwaddr node0_size = spapr_node0_size(machine);
    long load_limit, fw_size;
    char *filename;
    Error *resize_hpt_err = NULL;

    msi_nonbroken = true;

    QLIST_INIT(&spapr->phbs);
    QTAILQ_INIT(&spapr->pending_dimm_unplugs);

    /* Check HPT resizing availability */
    kvmppc_check_papr_resize_hpt(&resize_hpt_err);
    if (spapr->resize_hpt == SPAPR_RESIZE_HPT_DEFAULT) {
        /*
         * If the user explicitly requested a mode we should either
         * supply it, or fail completely (which we do below).  But if
         * it's not set explicitly, we reset our mode to something
         * that works
         */
        if (resize_hpt_err) {
            spapr->resize_hpt = SPAPR_RESIZE_HPT_DISABLED;
            error_free(resize_hpt_err);
            resize_hpt_err = NULL;
        } else {
            spapr->resize_hpt = smc->resize_hpt_default;
        }
    }

    assert(spapr->resize_hpt != SPAPR_RESIZE_HPT_DEFAULT);

    if ((spapr->resize_hpt != SPAPR_RESIZE_HPT_DISABLED) && resize_hpt_err) {
        /*
         * User requested HPT resize, but this host can't supply it.  Bail out
         */
        error_report_err(resize_hpt_err);
        exit(1);
    }

    /* Allocate RMA if necessary */
    rma_alloc_size = kvmppc_alloc_rma(&rma);

    if (rma_alloc_size == -1) {
        error_report("Unable to create RMA");
        exit(1);
    }

    if (rma_alloc_size && (rma_alloc_size < node0_size)) {
        spapr->rma_size = rma_alloc_size;
    } else {
        spapr->rma_size = node0_size;

        /* With KVM, we don't actually know whether KVM supports an
         * unbounded RMA (PR KVM) or is limited by the hash table size
         * (HV KVM using VRMA), so we always assume the latter
         *
         * In that case, we also limit the initial allocations for RTAS
         * etc... to 256M since we have no way to know what the VRMA size
         * is going to be as it depends on the size of the hash table
         * isn't determined yet.
         */
        if (kvm_enabled()) {
            spapr->vrma_adjust = 1;
            spapr->rma_size = MIN(spapr->rma_size, 0x10000000);
        }

        /* Actually we don't support unbounded RMA anymore since we
         * added proper emulation of HV mode. The max we can get is
         * 16G which also happens to be what we configure for PAPR
         * mode so make sure we don't do anything bigger than that
         */
        spapr->rma_size = MIN(spapr->rma_size, 0x400000000ull);
    }

    if (spapr->rma_size > node0_size) {
        error_report("Numa node 0 has to span the RMA (%#08"HWADDR_PRIx")",
                     spapr->rma_size);
        exit(1);
    }

    /* Setup a load limit for the ramdisk leaving room for SLOF and FDT */
    load_limit = MIN(spapr->rma_size, RTAS_MAX_ADDR) - FW_OVERHEAD;

    /* Set up Interrupt Controller before we create the VCPUs */
    xics_system_init(machine, XICS_IRQS_SPAPR, &error_fatal);

    /* Set up containers for ibm,client-architecture-support negotiated options
     */
    spapr->ov5 = spapr_ovec_new();
    spapr->ov5_cas = spapr_ovec_new();

    if (smc->dr_lmb_enabled) {
        spapr_ovec_set(spapr->ov5, OV5_DRCONF_MEMORY);
        spapr_validate_node_memory(machine, &error_fatal);
    }

    spapr_ovec_set(spapr->ov5, OV5_FORM1_AFFINITY);
    if (!kvm_enabled() || kvmppc_has_cap_mmu_radix()) {
        /* KVM and TCG always allow GTSE with radix... */
        spapr_ovec_set(spapr->ov5, OV5_MMU_RADIX_GTSE);
    }
    /* ... but not with hash (currently). */

    /* advertise support for dedicated HP event source to guests */
    if (spapr->use_hotplug_event_source) {
        spapr_ovec_set(spapr->ov5, OV5_HP_EVT);
    }

    /* advertise support for HPT resizing */
    if (spapr->resize_hpt != SPAPR_RESIZE_HPT_DISABLED) {
        spapr_ovec_set(spapr->ov5, OV5_HPT_RESIZE);
    }

    /* init CPUs */
    spapr_set_vsmt_mode(spapr, &error_fatal);

    spapr_init_cpus(spapr);

    if (kvm_enabled()) {
        /* Enable H_LOGICAL_CI_* so SLOF can talk to in-kernel devices */
        kvmppc_enable_logical_ci_hcalls();
        kvmppc_enable_set_mode_hcall();

        /* H_CLEAR_MOD/_REF are mandatory in PAPR, but off by default */
        kvmppc_enable_clear_ref_mod_hcalls();
    }

    /* allocate RAM */
    memory_region_allocate_system_memory(ram, NULL, "ppc_spapr.ram",
                                         machine->ram_size);
    memory_region_add_subregion(sysmem, 0, ram);

    if (rma_alloc_size && rma) {
        rma_region = g_new(MemoryRegion, 1);
        memory_region_init_ram_ptr(rma_region, NULL, "ppc_spapr.rma",
                                   rma_alloc_size, rma);
        vmstate_register_ram_global(rma_region);
        memory_region_add_subregion(sysmem, 0, rma_region);
    }

    /* initialize hotplug memory address space */
    if (machine->ram_size < machine->maxram_size) {
        ram_addr_t hotplug_mem_size = machine->maxram_size - machine->ram_size;
        /*
         * Limit the number of hotpluggable memory slots to half the number
         * slots that KVM supports, leaving the other half for PCI and other
         * devices. However ensure that number of slots doesn't drop below 32.
         */
        int max_memslots = kvm_enabled() ? kvm_get_max_memslots() / 2 :
                           SPAPR_MAX_RAM_SLOTS;

        if (max_memslots < SPAPR_MAX_RAM_SLOTS) {
            max_memslots = SPAPR_MAX_RAM_SLOTS;
        }
        if (machine->ram_slots > max_memslots) {
            error_report("Specified number of memory slots %"
                         PRIu64" exceeds max supported %d",
                         machine->ram_slots, max_memslots);
            exit(1);
        }

        spapr->hotplug_memory.base = ROUND_UP(machine->ram_size,
                                              SPAPR_HOTPLUG_MEM_ALIGN);
        memory_region_init(&spapr->hotplug_memory.mr, OBJECT(spapr),
                           "hotplug-memory", hotplug_mem_size);
        memory_region_add_subregion(sysmem, spapr->hotplug_memory.base,
                                    &spapr->hotplug_memory.mr);
    }

    if (smc->dr_lmb_enabled) {
        spapr_create_lmb_dr_connectors(spapr);
    }

    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, "spapr-rtas.bin");
    if (!filename) {
        error_report("Could not find LPAR rtas '%s'", "spapr-rtas.bin");
        exit(1);
    }
    spapr->rtas_size = get_image_size(filename);
    if (spapr->rtas_size < 0) {
        error_report("Could not get size of LPAR rtas '%s'", filename);
        exit(1);
    }
    spapr->rtas_blob = g_malloc(spapr->rtas_size);
    if (load_image_size(filename, spapr->rtas_blob, spapr->rtas_size) < 0) {
        error_report("Could not load LPAR rtas '%s'", filename);
        exit(1);
    }
    if (spapr->rtas_size > RTAS_MAX_SIZE) {
        error_report("RTAS too big ! 0x%zx bytes (max is 0x%x)",
                     (size_t)spapr->rtas_size, RTAS_MAX_SIZE);
        exit(1);
    }
    g_free(filename);

    /* Set up RTAS event infrastructure */
    spapr_events_init(spapr);

    /* Set up the RTC RTAS interfaces */
    spapr_rtc_create(spapr);

    /* Set up VIO bus */
    spapr->vio_bus = spapr_vio_bus_init();

    for (i = 0; i < MAX_SERIAL_PORTS; i++) {
        if (serial_hds[i]) {
            spapr_vty_create(spapr->vio_bus, serial_hds[i]);
        }
    }

    /* We always have at least the nvram device on VIO */
    spapr_create_nvram(spapr);

    /* Set up PCI */
    spapr_pci_rtas_init();

    phb = spapr_create_phb(spapr, 0);

    for (i = 0; i < nb_nics; i++) {
        NICInfo *nd = &nd_table[i];

        if (!nd->model) {
            nd->model = g_strdup("ibmveth");
        }

        if (strcmp(nd->model, "ibmveth") == 0) {
            spapr_vlan_create(spapr->vio_bus, nd);
        } else {
            pci_nic_init_nofail(&nd_table[i], phb->bus, nd->model, NULL);
        }
    }

    for (i = 0; i <= drive_get_max_bus(IF_SCSI); i++) {
        spapr_vscsi_create(spapr->vio_bus);
    }

    /* Graphics */
    if (spapr_vga_init(phb->bus, &error_fatal)) {
        spapr->has_graphics = true;
        machine->usb |= defaults_enabled() && !machine->usb_disabled;
    }

    if (machine->usb) {
        if (smc->use_ohci_by_default) {
            pci_create_simple(phb->bus, -1, "pci-ohci");
        } else {
            pci_create_simple(phb->bus, -1, "nec-usb-xhci");
        }

        if (spapr->has_graphics) {
            USBBus *usb_bus = usb_bus_find(-1);

            usb_create_simple(usb_bus, "usb-kbd");
            usb_create_simple(usb_bus, "usb-mouse");
        }
    }

    if (spapr->rma_size < (MIN_RMA_SLOF << 20)) {
        error_report(
            "pSeries SLOF firmware requires >= %ldM guest RMA (Real Mode Area memory)",
            MIN_RMA_SLOF);
        exit(1);
    }

    if (kernel_filename) {
        uint64_t lowaddr = 0;

        spapr->kernel_size = load_elf(kernel_filename, translate_kernel_address,
                                      NULL, NULL, &lowaddr, NULL, 1,
                                      PPC_ELF_MACHINE, 0, 0);
        if (spapr->kernel_size == ELF_LOAD_WRONG_ENDIAN) {
            spapr->kernel_size = load_elf(kernel_filename,
                                          translate_kernel_address, NULL, NULL,
                                          &lowaddr, NULL, 0, PPC_ELF_MACHINE,
                                          0, 0);
            spapr->kernel_le = spapr->kernel_size > 0;
        }
        if (spapr->kernel_size < 0) {
            error_report("error loading %s: %s", kernel_filename,
                         load_elf_strerror(spapr->kernel_size));
            exit(1);
        }

        /* load initrd */
        if (initrd_filename) {
            /* Try to locate the initrd in the gap between the kernel
             * and the firmware. Add a bit of space just in case
             */
            spapr->initrd_base = (KERNEL_LOAD_ADDR + spapr->kernel_size
                                  + 0x1ffff) & ~0xffff;
            spapr->initrd_size = load_image_targphys(initrd_filename,
                                                     spapr->initrd_base,
                                                     load_limit
                                                     - spapr->initrd_base);
            if (spapr->initrd_size < 0) {
                error_report("could not load initial ram disk '%s'",
                             initrd_filename);
                exit(1);
            }
        }
    }

    if (bios_name == NULL) {
        bios_name = FW_FILE_NAME;
    }
    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
    if (!filename) {
        error_report("Could not find LPAR firmware '%s'", bios_name);
        exit(1);
    }
    fw_size = load_image_targphys(filename, 0, FW_MAX_SIZE);
    if (fw_size <= 0) {
        error_report("Could not load LPAR firmware '%s'", filename);
        exit(1);
    }
    g_free(filename);

    /* FIXME: Should register things through the MachineState's qdev
     * interface, this is a legacy from the sPAPREnvironment structure
     * which predated MachineState but had a similar function */
    vmstate_register(NULL, 0, &vmstate_spapr, spapr);
    register_savevm_live(NULL, "spapr/htab", -1, 1,
                         &savevm_htab_handlers, spapr);

    qemu_register_boot_set(spapr_boot_set, spapr);

    if (kvm_enabled()) {
        /* to stop and start vmclock */
        qemu_add_vm_change_state_handler(cpu_ppc_clock_vm_state_change,
                                         &spapr->tb);

        kvmppc_spapr_enable_inkernel_multitce();
    }
}

static int spapr_kvm_type(const char *vm_type)
{
    if (!vm_type) {
        return 0;
    }

    if (!strcmp(vm_type, "HV")) {
        return 1;
    }

    if (!strcmp(vm_type, "PR")) {
        return 2;
    }

    error_report("Unknown kvm-type specified '%s'", vm_type);
    exit(1);
}

/*
 * Implementation of an interface to adjust firmware path
 * for the bootindex property handling.
 */
static char *spapr_get_fw_dev_path(FWPathProvider *p, BusState *bus,
                                   DeviceState *dev)
{
#define CAST(type, obj, name) \
    ((type *)object_dynamic_cast(OBJECT(obj), (name)))
    SCSIDevice *d = CAST(SCSIDevice,  dev, TYPE_SCSI_DEVICE);
    sPAPRPHBState *phb = CAST(sPAPRPHBState, dev, TYPE_SPAPR_PCI_HOST_BRIDGE);
    VHostSCSICommon *vsc = CAST(VHostSCSICommon, dev, TYPE_VHOST_SCSI_COMMON);

    if (d) {
        void *spapr = CAST(void, bus->parent, "spapr-vscsi");
        VirtIOSCSI *virtio = CAST(VirtIOSCSI, bus->parent, TYPE_VIRTIO_SCSI);
        USBDevice *usb = CAST(USBDevice, bus->parent, TYPE_USB_DEVICE);

        if (spapr) {
            /*
             * Replace "channel@0/disk@0,0" with "disk@8000000000000000":
             * We use SRP luns of the form 8000 | (bus << 8) | (id << 5) | lun
             * in the top 16 bits of the 64-bit LUN
             */
            unsigned id = 0x8000 | (d->id << 8) | d->lun;
            return g_strdup_printf("%s@%"PRIX64, qdev_fw_name(dev),
                                   (uint64_t)id << 48);
        } else if (virtio) {
            /*
             * We use SRP luns of the form 01000000 | (target << 8) | lun
             * in the top 32 bits of the 64-bit LUN
             * Note: the quote above is from SLOF and it is wrong,
             * the actual binding is:
             * swap 0100 or 10 << or 20 << ( target lun-id -- srplun )
             */
            unsigned id = 0x1000000 | (d->id << 16) | d->lun;
            if (d->lun >= 256) {
                /* Use the LUN "flat space addressing method" */
                id |= 0x4000;
            }
            return g_strdup_printf("%s@%"PRIX64, qdev_fw_name(dev),
                                   (uint64_t)id << 32);
        } else if (usb) {
            /*
             * We use SRP luns of the form 01000000 | (usb-port << 16) | lun
             * in the top 32 bits of the 64-bit LUN
             */
            unsigned usb_port = atoi(usb->port->path);
            unsigned id = 0x1000000 | (usb_port << 16) | d->lun;
            return g_strdup_printf("%s@%"PRIX64, qdev_fw_name(dev),
                                   (uint64_t)id << 32);
        }
    }

    /*
     * SLOF probes the USB devices, and if it recognizes that the device is a
     * storage device, it changes its name to "storage" instead of "usb-host",
     * and additionally adds a child node for the SCSI LUN, so the correct
     * boot path in SLOF is something like .../storage@1/disk@xxx" instead.
     */
    if (strcmp("usb-host", qdev_fw_name(dev)) == 0) {
        USBDevice *usbdev = CAST(USBDevice, dev, TYPE_USB_DEVICE);
        if (usb_host_dev_is_scsi_storage(usbdev)) {
            return g_strdup_printf("storage@%s/disk", usbdev->port->path);
        }
    }

    if (phb) {
        /* Replace "pci" with "pci@800000020000000" */
        return g_strdup_printf("pci@%"PRIX64, phb->buid);
    }

    if (vsc) {
        /* Same logic as virtio above */
        unsigned id = 0x1000000 | (vsc->target << 16) | vsc->lun;
        return g_strdup_printf("disk@%"PRIX64, (uint64_t)id << 32);
    }

    if (g_str_equal("pci-bridge", qdev_fw_name(dev))) {
        /* SLOF uses "pci" instead of "pci-bridge" for PCI bridges */
        PCIDevice *pcidev = CAST(PCIDevice, dev, TYPE_PCI_DEVICE);
        return g_strdup_printf("pci@%x", PCI_SLOT(pcidev->devfn));
    }

    return NULL;
}

static char *spapr_get_kvm_type(Object *obj, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    return g_strdup(spapr->kvm_type);
}

static void spapr_set_kvm_type(Object *obj, const char *value, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    g_free(spapr->kvm_type);
    spapr->kvm_type = g_strdup(value);
}

static bool spapr_get_modern_hotplug_events(Object *obj, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    return spapr->use_hotplug_event_source;
}

static void spapr_set_modern_hotplug_events(Object *obj, bool value,
                                            Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    spapr->use_hotplug_event_source = value;
}

static char *spapr_get_resize_hpt(Object *obj, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    switch (spapr->resize_hpt) {
    case SPAPR_RESIZE_HPT_DEFAULT:
        return g_strdup("default");
    case SPAPR_RESIZE_HPT_DISABLED:
        return g_strdup("disabled");
    case SPAPR_RESIZE_HPT_ENABLED:
        return g_strdup("enabled");
    case SPAPR_RESIZE_HPT_REQUIRED:
        return g_strdup("required");
    }
    g_assert_not_reached();
}

static void spapr_set_resize_hpt(Object *obj, const char *value, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    if (strcmp(value, "default") == 0) {
        spapr->resize_hpt = SPAPR_RESIZE_HPT_DEFAULT;
    } else if (strcmp(value, "disabled") == 0) {
        spapr->resize_hpt = SPAPR_RESIZE_HPT_DISABLED;
    } else if (strcmp(value, "enabled") == 0) {
        spapr->resize_hpt = SPAPR_RESIZE_HPT_ENABLED;
    } else if (strcmp(value, "required") == 0) {
        spapr->resize_hpt = SPAPR_RESIZE_HPT_REQUIRED;
    } else {
        error_setg(errp, "Bad value for \"resize-hpt\" property");
    }
}

static void spapr_get_vsmt(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    visit_type_uint32(v, name, (uint32_t *)opaque, errp);
}

static void spapr_set_vsmt(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    visit_type_uint32(v, name, (uint32_t *)opaque, errp);
}

static void spapr_instance_init(Object *obj)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    spapr->htab_fd = -1;
    spapr->use_hotplug_event_source = true;
    object_property_add_str(obj, "kvm-type",
                            spapr_get_kvm_type, spapr_set_kvm_type, NULL);
    object_property_set_description(obj, "kvm-type",
                                    "Specifies the KVM virtualization mode (HV, PR)",
                                    NULL);
    object_property_add_bool(obj, "modern-hotplug-events",
                            spapr_get_modern_hotplug_events,
                            spapr_set_modern_hotplug_events,
                            NULL);
    object_property_set_description(obj, "modern-hotplug-events",
                                    "Use dedicated hotplug event mechanism in"
                                    " place of standard EPOW events when possible"
                                    " (required for memory hot-unplug support)",
                                    NULL);

    ppc_compat_add_property(obj, "max-cpu-compat", &spapr->max_compat_pvr,
                            "Maximum permitted CPU compatibility mode",
                            &error_fatal);

    object_property_add_str(obj, "resize-hpt",
                            spapr_get_resize_hpt, spapr_set_resize_hpt, NULL);
    object_property_set_description(obj, "resize-hpt",
                                    "Resizing of the Hash Page Table (enabled, disabled, required)",
                                    NULL);
    object_property_add(obj, "vsmt", "uint32", spapr_get_vsmt,
                        spapr_set_vsmt, NULL, &spapr->vsmt, &error_abort);
    object_property_set_description(obj, "vsmt",
                                    "Virtual SMT: KVM behaves as if this were"
                                    " the host's SMT mode", &error_abort);
}

static void spapr_machine_finalizefn(Object *obj)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);

    g_free(spapr->kvm_type);
}

void spapr_do_system_reset_on_cpu(CPUState *cs, run_on_cpu_data arg)
{
    cpu_synchronize_state(cs);
    ppc_cpu_do_system_reset(cs);
}

static void spapr_nmi(NMIState *n, int cpu_index, Error **errp)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        async_run_on_cpu(cs, spapr_do_system_reset_on_cpu, RUN_ON_CPU_NULL);
    }
}

static void spapr_add_lmbs(DeviceState *dev, uint64_t addr_start, uint64_t size,
                           uint32_t node, bool dedicated_hp_event_source,
                           Error **errp)
{
    sPAPRDRConnector *drc;
    uint32_t nr_lmbs = size/SPAPR_MEMORY_BLOCK_SIZE;
    int i, fdt_offset, fdt_size;
    void *fdt;
    uint64_t addr = addr_start;
    bool hotplugged = spapr_drc_hotplugged(dev);
    Error *local_err = NULL;

    for (i = 0; i < nr_lmbs; i++) {
        drc = spapr_drc_by_id(TYPE_SPAPR_DRC_LMB,
                              addr / SPAPR_MEMORY_BLOCK_SIZE);
        g_assert(drc);

        fdt = create_device_tree(&fdt_size);
        fdt_offset = spapr_populate_memory_node(fdt, node, addr,
                                                SPAPR_MEMORY_BLOCK_SIZE);

        spapr_drc_attach(drc, dev, fdt, fdt_offset, &local_err);
        if (local_err) {
            while (addr > addr_start) {
                addr -= SPAPR_MEMORY_BLOCK_SIZE;
                drc = spapr_drc_by_id(TYPE_SPAPR_DRC_LMB,
                                      addr / SPAPR_MEMORY_BLOCK_SIZE);
                spapr_drc_detach(drc);
            }
            g_free(fdt);
            error_propagate(errp, local_err);
            return;
        }
        if (!hotplugged) {
            spapr_drc_reset(drc);
        }
        addr += SPAPR_MEMORY_BLOCK_SIZE;
    }
    /* send hotplug notification to the
     * guest only in case of hotplugged memory
     */
    if (hotplugged) {
        if (dedicated_hp_event_source) {
            drc = spapr_drc_by_id(TYPE_SPAPR_DRC_LMB,
                                  addr_start / SPAPR_MEMORY_BLOCK_SIZE);
            spapr_hotplug_req_add_by_count_indexed(SPAPR_DR_CONNECTOR_TYPE_LMB,
                                                   nr_lmbs,
                                                   spapr_drc_index(drc));
        } else {
            spapr_hotplug_req_add_by_count(SPAPR_DR_CONNECTOR_TYPE_LMB,
                                           nr_lmbs);
        }
    }
}

static void spapr_memory_plug(HotplugHandler *hotplug_dev, DeviceState *dev,
                              uint32_t node, Error **errp)
{
    Error *local_err = NULL;
    sPAPRMachineState *ms = SPAPR_MACHINE(hotplug_dev);
    PCDIMMDevice *dimm = PC_DIMM(dev);
    PCDIMMDeviceClass *ddc = PC_DIMM_GET_CLASS(dimm);
    MemoryRegion *mr;
    uint64_t align, size, addr;

    mr = ddc->get_memory_region(dimm, &local_err);
    if (local_err) {
        goto out;
    }
    align = memory_region_get_alignment(mr);
    size = memory_region_size(mr);

    pc_dimm_memory_plug(dev, &ms->hotplug_memory, mr, align, &local_err);
    if (local_err) {
        goto out;
    }

    addr = object_property_get_uint(OBJECT(dimm),
                                    PC_DIMM_ADDR_PROP, &local_err);
    if (local_err) {
        goto out_unplug;
    }

    spapr_add_lmbs(dev, addr, size, node,
                   spapr_ovec_test(ms->ov5_cas, OV5_HP_EVT),
                   &local_err);
    if (local_err) {
        goto out_unplug;
    }

    return;

out_unplug:
    pc_dimm_memory_unplug(dev, &ms->hotplug_memory, mr);
out:
    error_propagate(errp, local_err);
}

static void spapr_memory_pre_plug(HotplugHandler *hotplug_dev, DeviceState *dev,
                                  Error **errp)
{
    PCDIMMDevice *dimm = PC_DIMM(dev);
    PCDIMMDeviceClass *ddc = PC_DIMM_GET_CLASS(dimm);
    MemoryRegion *mr;
    uint64_t size;
    char *mem_dev;

    mr = ddc->get_memory_region(dimm, errp);
    if (!mr) {
        return;
    }
    size = memory_region_size(mr);

    if (size % SPAPR_MEMORY_BLOCK_SIZE) {
        error_setg(errp, "Hotplugged memory size must be a multiple of "
                      "%lld MB", SPAPR_MEMORY_BLOCK_SIZE / M_BYTE);
        return;
    }

    mem_dev = object_property_get_str(OBJECT(dimm), PC_DIMM_MEMDEV_PROP, NULL);
    if (mem_dev && !kvmppc_is_mem_backend_page_size_ok(mem_dev)) {
        error_setg(errp, "Memory backend has bad page size. "
                   "Use 'memory-backend-file' with correct mem-path.");
        goto out;
    }

out:
    g_free(mem_dev);
}

struct sPAPRDIMMState {
    PCDIMMDevice *dimm;
    uint32_t nr_lmbs;
    QTAILQ_ENTRY(sPAPRDIMMState) next;
};

static sPAPRDIMMState *spapr_pending_dimm_unplugs_find(sPAPRMachineState *s,
                                                       PCDIMMDevice *dimm)
{
    sPAPRDIMMState *dimm_state = NULL;

    QTAILQ_FOREACH(dimm_state, &s->pending_dimm_unplugs, next) {
        if (dimm_state->dimm == dimm) {
            break;
        }
    }
    return dimm_state;
}

static sPAPRDIMMState *spapr_pending_dimm_unplugs_add(sPAPRMachineState *spapr,
                                                      uint32_t nr_lmbs,
                                                      PCDIMMDevice *dimm)
{
    sPAPRDIMMState *ds = NULL;

    /*
     * If this request is for a DIMM whose removal had failed earlier
     * (due to guest's refusal to remove the LMBs), we would have this
     * dimm already in the pending_dimm_unplugs list. In that
     * case don't add again.
     */
    ds = spapr_pending_dimm_unplugs_find(spapr, dimm);
    if (!ds) {
        ds = g_malloc0(sizeof(sPAPRDIMMState));
        ds->nr_lmbs = nr_lmbs;
        ds->dimm = dimm;
        QTAILQ_INSERT_HEAD(&spapr->pending_dimm_unplugs, ds, next);
    }
    return ds;
}

static void spapr_pending_dimm_unplugs_remove(sPAPRMachineState *spapr,
                                              sPAPRDIMMState *dimm_state)
{
    QTAILQ_REMOVE(&spapr->pending_dimm_unplugs, dimm_state, next);
    g_free(dimm_state);
}

static sPAPRDIMMState *spapr_recover_pending_dimm_state(sPAPRMachineState *ms,
                                                        PCDIMMDevice *dimm)
{
    sPAPRDRConnector *drc;
    PCDIMMDeviceClass *ddc = PC_DIMM_GET_CLASS(dimm);
    MemoryRegion *mr = ddc->get_memory_region(dimm, &error_abort);
    uint64_t size = memory_region_size(mr);
    uint32_t nr_lmbs = size / SPAPR_MEMORY_BLOCK_SIZE;
    uint32_t avail_lmbs = 0;
    uint64_t addr_start, addr;
    int i;

    addr_start = object_property_get_int(OBJECT(dimm), PC_DIMM_ADDR_PROP,
                                         &error_abort);

    addr = addr_start;
    for (i = 0; i < nr_lmbs; i++) {
        drc = spapr_drc_by_id(TYPE_SPAPR_DRC_LMB,
                              addr / SPAPR_MEMORY_BLOCK_SIZE);
        g_assert(drc);
        if (drc->dev) {
            avail_lmbs++;
        }
        addr += SPAPR_MEMORY_BLOCK_SIZE;
    }

    return spapr_pending_dimm_unplugs_add(ms, avail_lmbs, dimm);
}

/* Callback to be called during DRC release. */
void spapr_lmb_release(DeviceState *dev)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(qdev_get_hotplug_handler(dev));
    PCDIMMDevice *dimm = PC_DIMM(dev);
    PCDIMMDeviceClass *ddc = PC_DIMM_GET_CLASS(dimm);
    MemoryRegion *mr = ddc->get_memory_region(dimm, &error_abort);
    sPAPRDIMMState *ds = spapr_pending_dimm_unplugs_find(spapr, PC_DIMM(dev));

    /* This information will get lost if a migration occurs
     * during the unplug process. In this case recover it. */
    if (ds == NULL) {
        ds = spapr_recover_pending_dimm_state(spapr, PC_DIMM(dev));
        g_assert(ds);
        /* The DRC being examined by the caller at least must be counted */
        g_assert(ds->nr_lmbs);
    }

    if (--ds->nr_lmbs) {
        return;
    }

    /*
     * Now that all the LMBs have been removed by the guest, call the
     * pc-dimm unplug handler to cleanup up the pc-dimm device.
     */
    pc_dimm_memory_unplug(dev, &spapr->hotplug_memory, mr);
    object_unparent(OBJECT(dev));
    spapr_pending_dimm_unplugs_remove(spapr, ds);
}

static void spapr_memory_unplug_request(HotplugHandler *hotplug_dev,
                                        DeviceState *dev, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(hotplug_dev);
    Error *local_err = NULL;
    PCDIMMDevice *dimm = PC_DIMM(dev);
    PCDIMMDeviceClass *ddc = PC_DIMM_GET_CLASS(dimm);
    MemoryRegion *mr;
    uint32_t nr_lmbs;
    uint64_t size, addr_start, addr;
    int i;
    sPAPRDRConnector *drc;

    mr = ddc->get_memory_region(dimm, &local_err);
    if (local_err) {
        goto out;
    }
    size = memory_region_size(mr);
    nr_lmbs = size / SPAPR_MEMORY_BLOCK_SIZE;

    addr_start = object_property_get_uint(OBJECT(dimm), PC_DIMM_ADDR_PROP,
                                         &local_err);
    if (local_err) {
        goto out;
    }

    /*
     * An existing pending dimm state for this DIMM means that there is an
     * unplug operation in progress, waiting for the spapr_lmb_release
     * callback to complete the job (BQL can't cover that far). In this case,
     * bail out to avoid detaching DRCs that were already released.
     */
    if (spapr_pending_dimm_unplugs_find(spapr, dimm)) {
        error_setg(&local_err,
                   "Memory unplug already in progress for device %s",
                   dev->id);
        goto out;
    }

    spapr_pending_dimm_unplugs_add(spapr, nr_lmbs, dimm);

    addr = addr_start;
    for (i = 0; i < nr_lmbs; i++) {
        drc = spapr_drc_by_id(TYPE_SPAPR_DRC_LMB,
                              addr / SPAPR_MEMORY_BLOCK_SIZE);
        g_assert(drc);

        spapr_drc_detach(drc);
        addr += SPAPR_MEMORY_BLOCK_SIZE;
    }

    drc = spapr_drc_by_id(TYPE_SPAPR_DRC_LMB,
                          addr_start / SPAPR_MEMORY_BLOCK_SIZE);
    spapr_hotplug_req_remove_by_count_indexed(SPAPR_DR_CONNECTOR_TYPE_LMB,
                                              nr_lmbs, spapr_drc_index(drc));
out:
    error_propagate(errp, local_err);
}

static void *spapr_populate_hotplug_cpu_dt(CPUState *cs, int *fdt_offset,
                                           sPAPRMachineState *spapr)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    DeviceClass *dc = DEVICE_GET_CLASS(cs);
    int id = spapr_get_vcpu_id(cpu);
    void *fdt;
    int offset, fdt_size;
    char *nodename;

    fdt = create_device_tree(&fdt_size);
    nodename = g_strdup_printf("%s@%x", dc->fw_name, id);
    offset = fdt_add_subnode(fdt, 0, nodename);

    spapr_populate_cpu_dt(cs, fdt, offset, spapr);
    g_free(nodename);

    *fdt_offset = offset;
    return fdt;
}

/* Callback to be called during DRC release. */
void spapr_core_release(DeviceState *dev)
{
    MachineState *ms = MACHINE(qdev_get_hotplug_handler(dev));
    sPAPRMachineClass *smc = SPAPR_MACHINE_GET_CLASS(ms);
    CPUCore *cc = CPU_CORE(dev);
    CPUArchId *core_slot = spapr_find_cpu_slot(ms, cc->core_id, NULL);

    if (smc->pre_2_10_has_unused_icps) {
        sPAPRCPUCore *sc = SPAPR_CPU_CORE(OBJECT(dev));
        int i;

        for (i = 0; i < cc->nr_threads; i++) {
            CPUState *cs = CPU(sc->threads[i]);

            pre_2_10_vmstate_register_dummy_icp(cs->cpu_index);
        }
    }

    assert(core_slot);
    core_slot->cpu = NULL;
    object_unparent(OBJECT(dev));
}

static
void spapr_core_unplug_request(HotplugHandler *hotplug_dev, DeviceState *dev,
                               Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(OBJECT(hotplug_dev));
    int index;
    sPAPRDRConnector *drc;
    CPUCore *cc = CPU_CORE(dev);

    if (!spapr_find_cpu_slot(MACHINE(hotplug_dev), cc->core_id, &index)) {
        error_setg(errp, "Unable to find CPU core with core-id: %d",
                   cc->core_id);
        return;
    }
    if (index == 0) {
        error_setg(errp, "Boot CPU core may not be unplugged");
        return;
    }

    drc = spapr_drc_by_id(TYPE_SPAPR_DRC_CPU,
                          spapr_vcpu_id(spapr, cc->core_id));
    g_assert(drc);

    spapr_drc_detach(drc);

    spapr_hotplug_req_remove_by_index(drc);
}

static void spapr_core_plug(HotplugHandler *hotplug_dev, DeviceState *dev,
                            Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(OBJECT(hotplug_dev));
    MachineClass *mc = MACHINE_GET_CLASS(spapr);
    sPAPRMachineClass *smc = SPAPR_MACHINE_CLASS(mc);
    sPAPRCPUCore *core = SPAPR_CPU_CORE(OBJECT(dev));
    CPUCore *cc = CPU_CORE(dev);
    CPUState *cs = CPU(core->threads[0]);
    sPAPRDRConnector *drc;
    Error *local_err = NULL;
    CPUArchId *core_slot;
    int index;
    bool hotplugged = spapr_drc_hotplugged(dev);

    core_slot = spapr_find_cpu_slot(MACHINE(hotplug_dev), cc->core_id, &index);
    if (!core_slot) {
        error_setg(errp, "Unable to find CPU core with core-id: %d",
                   cc->core_id);
        return;
    }
    drc = spapr_drc_by_id(TYPE_SPAPR_DRC_CPU,
                          spapr_vcpu_id(spapr, cc->core_id));

    g_assert(drc || !mc->has_hotpluggable_cpus);

    if (drc) {
        void *fdt;
        int fdt_offset;

        fdt = spapr_populate_hotplug_cpu_dt(cs, &fdt_offset, spapr);

        spapr_drc_attach(drc, dev, fdt, fdt_offset, &local_err);
        if (local_err) {
            g_free(fdt);
            error_propagate(errp, local_err);
            return;
        }

        if (hotplugged) {
            /*
             * Send hotplug notification interrupt to the guest only
             * in case of hotplugged CPUs.
             */
            spapr_hotplug_req_add_by_index(drc);
        } else {
            spapr_drc_reset(drc);
        }
    }

    core_slot->cpu = OBJECT(dev);

    if (smc->pre_2_10_has_unused_icps) {
        int i;

        for (i = 0; i < cc->nr_threads; i++) {
            cs = CPU(core->threads[i]);
            pre_2_10_vmstate_unregister_dummy_icp(cs->cpu_index);
        }
    }
}

static void spapr_core_pre_plug(HotplugHandler *hotplug_dev, DeviceState *dev,
                                Error **errp)
{
    MachineState *machine = MACHINE(OBJECT(hotplug_dev));
    MachineClass *mc = MACHINE_GET_CLASS(hotplug_dev);
    Error *local_err = NULL;
    CPUCore *cc = CPU_CORE(dev);
    const char *base_core_type = spapr_get_cpu_core_type(machine->cpu_type);
    const char *type = object_get_typename(OBJECT(dev));
    CPUArchId *core_slot;
    int index;

    if (dev->hotplugged && !mc->has_hotpluggable_cpus) {
        error_setg(&local_err, "CPU hotplug not supported for this machine");
        goto out;
    }

    if (strcmp(base_core_type, type)) {
        error_setg(&local_err, "CPU core type should be %s", base_core_type);
        goto out;
    }

    if (cc->core_id % smp_threads) {
        error_setg(&local_err, "invalid core id %d", cc->core_id);
        goto out;
    }

    /*
     * In general we should have homogeneous threads-per-core, but old
     * (pre hotplug support) machine types allow the last core to have
     * reduced threads as a compatibility hack for when we allowed
     * total vcpus not a multiple of threads-per-core.
     */
    if (mc->has_hotpluggable_cpus && (cc->nr_threads != smp_threads)) {
        error_setg(&local_err, "invalid nr-threads %d, must be %d",
                   cc->nr_threads, smp_threads);
        goto out;
    }

    core_slot = spapr_find_cpu_slot(MACHINE(hotplug_dev), cc->core_id, &index);
    if (!core_slot) {
        error_setg(&local_err, "core id %d out of range", cc->core_id);
        goto out;
    }

    if (core_slot->cpu) {
        error_setg(&local_err, "core %d already populated", cc->core_id);
        goto out;
    }

    numa_cpu_pre_plug(core_slot, dev, &local_err);

out:
    error_propagate(errp, local_err);
}

static void spapr_machine_device_plug(HotplugHandler *hotplug_dev,
                                      DeviceState *dev, Error **errp)
{
    MachineState *ms = MACHINE(hotplug_dev);
    sPAPRMachineClass *smc = SPAPR_MACHINE_GET_CLASS(ms);

    if (object_dynamic_cast(OBJECT(dev), TYPE_PC_DIMM)) {
        int node;

        if (!smc->dr_lmb_enabled) {
            error_setg(errp, "Memory hotplug not supported for this machine");
            return;
        }
        node = object_property_get_uint(OBJECT(dev), PC_DIMM_NODE_PROP, errp);
        if (*errp) {
            return;
        }
        if (node < 0 || node >= MAX_NODES) {
            error_setg(errp, "Invaild node %d", node);
            return;
        }

        /*
         * Currently PowerPC kernel doesn't allow hot-adding memory to
         * memory-less node, but instead will silently add the memory
         * to the first node that has some memory. This causes two
         * unexpected behaviours for the user.
         *
         * - Memory gets hotplugged to a different node than what the user
         *   specified.
         * - Since pc-dimm subsystem in QEMU still thinks that memory belongs
         *   to memory-less node, a reboot will set things accordingly
         *   and the previously hotplugged memory now ends in the right node.
         *   This appears as if some memory moved from one node to another.
         *
         * So until kernel starts supporting memory hotplug to memory-less
         * nodes, just prevent such attempts upfront in QEMU.
         */
        if (nb_numa_nodes && !numa_info[node].node_mem) {
            error_setg(errp, "Can't hotplug memory to memory-less node %d",
                       node);
            return;
        }

        spapr_memory_plug(hotplug_dev, dev, node, errp);
    } else if (object_dynamic_cast(OBJECT(dev), TYPE_SPAPR_CPU_CORE)) {
        spapr_core_plug(hotplug_dev, dev, errp);
    }
}

static void spapr_machine_device_unplug_request(HotplugHandler *hotplug_dev,
                                                DeviceState *dev, Error **errp)
{
    sPAPRMachineState *sms = SPAPR_MACHINE(OBJECT(hotplug_dev));
    MachineClass *mc = MACHINE_GET_CLASS(sms);

    if (object_dynamic_cast(OBJECT(dev), TYPE_PC_DIMM)) {
        if (spapr_ovec_test(sms->ov5_cas, OV5_HP_EVT)) {
            spapr_memory_unplug_request(hotplug_dev, dev, errp);
        } else {
            /* NOTE: this means there is a window after guest reset, prior to
             * CAS negotiation, where unplug requests will fail due to the
             * capability not being detected yet. This is a bit different than
             * the case with PCI unplug, where the events will be queued and
             * eventually handled by the guest after boot
             */
            error_setg(errp, "Memory hot unplug not supported for this guest");
        }
    } else if (object_dynamic_cast(OBJECT(dev), TYPE_SPAPR_CPU_CORE)) {
        if (!mc->has_hotpluggable_cpus) {
            error_setg(errp, "CPU hot unplug not supported on this machine");
            return;
        }
        spapr_core_unplug_request(hotplug_dev, dev, errp);
    }
}

static void spapr_machine_device_pre_plug(HotplugHandler *hotplug_dev,
                                          DeviceState *dev, Error **errp)
{
    if (object_dynamic_cast(OBJECT(dev), TYPE_PC_DIMM)) {
        spapr_memory_pre_plug(hotplug_dev, dev, errp);
    } else if (object_dynamic_cast(OBJECT(dev), TYPE_SPAPR_CPU_CORE)) {
        spapr_core_pre_plug(hotplug_dev, dev, errp);
    }
}

static HotplugHandler *spapr_get_hotplug_handler(MachineState *machine,
                                                 DeviceState *dev)
{
    if (object_dynamic_cast(OBJECT(dev), TYPE_PC_DIMM) ||
        object_dynamic_cast(OBJECT(dev), TYPE_SPAPR_CPU_CORE)) {
        return HOTPLUG_HANDLER(machine);
    }
    return NULL;
}

static CpuInstanceProperties
spapr_cpu_index_to_props(MachineState *machine, unsigned cpu_index)
{
    CPUArchId *core_slot;
    MachineClass *mc = MACHINE_GET_CLASS(machine);

    /* make sure possible_cpu are intialized */
    mc->possible_cpu_arch_ids(machine);
    /* get CPU core slot containing thread that matches cpu_index */
    core_slot = spapr_find_cpu_slot(machine, cpu_index, NULL);
    assert(core_slot);
    return core_slot->props;
}

static int64_t spapr_get_default_cpu_node_id(const MachineState *ms, int idx)
{
    return idx / smp_cores % nb_numa_nodes;
}

static const CPUArchIdList *spapr_possible_cpu_arch_ids(MachineState *machine)
{
    int i;
    const char *core_type;
    int spapr_max_cores = max_cpus / smp_threads;
    MachineClass *mc = MACHINE_GET_CLASS(machine);

    if (!mc->has_hotpluggable_cpus) {
        spapr_max_cores = QEMU_ALIGN_UP(smp_cpus, smp_threads) / smp_threads;
    }
    if (machine->possible_cpus) {
        assert(machine->possible_cpus->len == spapr_max_cores);
        return machine->possible_cpus;
    }

    core_type = spapr_get_cpu_core_type(machine->cpu_type);
    if (!core_type) {
        error_report("Unable to find sPAPR CPU Core definition");
        exit(1);
    }

    machine->possible_cpus = g_malloc0(sizeof(CPUArchIdList) +
                             sizeof(CPUArchId) * spapr_max_cores);
    machine->possible_cpus->len = spapr_max_cores;
    for (i = 0; i < machine->possible_cpus->len; i++) {
        int core_id = i * smp_threads;

        machine->possible_cpus->cpus[i].type = core_type;
        machine->possible_cpus->cpus[i].vcpus_count = smp_threads;
        machine->possible_cpus->cpus[i].arch_id = core_id;
        machine->possible_cpus->cpus[i].props.has_core_id = true;
        machine->possible_cpus->cpus[i].props.core_id = core_id;
    }
    return machine->possible_cpus;
}

static void spapr_phb_placement(sPAPRMachineState *spapr, uint32_t index,
                                uint64_t *buid, hwaddr *pio,
                                hwaddr *mmio32, hwaddr *mmio64,
                                unsigned n_dma, uint32_t *liobns, Error **errp)
{
    /*
     * New-style PHB window placement.
     *
     * Goals: Gives large (1TiB), naturally aligned 64-bit MMIO window
     * for each PHB, in addition to 2GiB 32-bit MMIO and 64kiB PIO
     * windows.
     *
     * Some guest kernels can't work with MMIO windows above 1<<46
     * (64TiB), so we place up to 31 PHBs in the area 32TiB..64TiB
     *
     * 32TiB..(33TiB+1984kiB) contains the 64kiB PIO windows for each
     * PHB stacked together.  (32TiB+2GiB)..(32TiB+64GiB) contains the
     * 2GiB 32-bit MMIO windows for each PHB.  Then 33..64TiB has the
     * 1TiB 64-bit MMIO windows for each PHB.
     */
    const uint64_t base_buid = 0x800000020000000ULL;
#define SPAPR_MAX_PHBS ((SPAPR_PCI_LIMIT - SPAPR_PCI_BASE) / \
                        SPAPR_PCI_MEM64_WIN_SIZE - 1)
    int i;

    /* Sanity check natural alignments */
    QEMU_BUILD_BUG_ON((SPAPR_PCI_BASE % SPAPR_PCI_MEM64_WIN_SIZE) != 0);
    QEMU_BUILD_BUG_ON((SPAPR_PCI_LIMIT % SPAPR_PCI_MEM64_WIN_SIZE) != 0);
    QEMU_BUILD_BUG_ON((SPAPR_PCI_MEM64_WIN_SIZE % SPAPR_PCI_MEM32_WIN_SIZE) != 0);
    QEMU_BUILD_BUG_ON((SPAPR_PCI_MEM32_WIN_SIZE % SPAPR_PCI_IO_WIN_SIZE) != 0);
    /* Sanity check bounds */
    QEMU_BUILD_BUG_ON((SPAPR_MAX_PHBS * SPAPR_PCI_IO_WIN_SIZE) >
                      SPAPR_PCI_MEM32_WIN_SIZE);
    QEMU_BUILD_BUG_ON((SPAPR_MAX_PHBS * SPAPR_PCI_MEM32_WIN_SIZE) >
                      SPAPR_PCI_MEM64_WIN_SIZE);

    if (index >= SPAPR_MAX_PHBS) {
        error_setg(errp, "\"index\" for PAPR PHB is too large (max %llu)",
                   SPAPR_MAX_PHBS - 1);
        return;
    }

    *buid = base_buid + index;
    for (i = 0; i < n_dma; ++i) {
        liobns[i] = SPAPR_PCI_LIOBN(index, i);
    }

    *pio = SPAPR_PCI_BASE + index * SPAPR_PCI_IO_WIN_SIZE;
    *mmio32 = SPAPR_PCI_BASE + (index + 1) * SPAPR_PCI_MEM32_WIN_SIZE;
    *mmio64 = SPAPR_PCI_BASE + (index + 1) * SPAPR_PCI_MEM64_WIN_SIZE;
}

static ICSState *spapr_ics_get(XICSFabric *dev, int irq)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(dev);

    return ics_valid_irq(spapr->ics, irq) ? spapr->ics : NULL;
}

static void spapr_ics_resend(XICSFabric *dev)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(dev);

    ics_resend(spapr->ics);
}

static ICPState *spapr_icp_get(XICSFabric *xi, int vcpu_id)
{
    PowerPCCPU *cpu = spapr_find_cpu(vcpu_id);

    return cpu ? ICP(cpu->intc) : NULL;
}

#define ICS_IRQ_FREE(ics, srcno)   \
    (!((ics)->irqs[(srcno)].flags & (XICS_FLAGS_IRQ_MASK)))

static int ics_find_free_block(ICSState *ics, int num, int alignnum)
{
    int first, i;

    for (first = 0; first < ics->nr_irqs; first += alignnum) {
        if (num > (ics->nr_irqs - first)) {
            return -1;
        }
        for (i = first; i < first + num; ++i) {
            if (!ICS_IRQ_FREE(ics, i)) {
                break;
            }
        }
        if (i == (first + num)) {
            return first;
        }
    }

    return -1;
}

/*
 * Allocate the IRQ number and set the IRQ type, LSI or MSI
 */
static void spapr_irq_set_lsi(sPAPRMachineState *spapr, int irq, bool lsi)
{
    ics_set_irq_type(spapr->ics, irq - spapr->ics->offset, lsi);
}

int spapr_irq_alloc(sPAPRMachineState *spapr, int irq_hint, bool lsi,
                    Error **errp)
{
    ICSState *ics = spapr->ics;
    int irq;

    if (!ics) {
        return -1;
    }
    if (irq_hint) {
        if (!ICS_IRQ_FREE(ics, irq_hint - ics->offset)) {
            error_setg(errp, "can't allocate IRQ %d: already in use", irq_hint);
            return -1;
        }
        irq = irq_hint;
    } else {
        irq = ics_find_free_block(ics, 1, 1);
        if (irq < 0) {
            error_setg(errp, "can't allocate IRQ: no IRQ left");
            return -1;
        }
        irq += ics->offset;
    }

    spapr_irq_set_lsi(spapr, irq, lsi);
    trace_spapr_irq_alloc(irq);

    return irq;
}

/*
 * Allocate block of consecutive IRQs, and return the number of the first IRQ in
 * the block. If align==true, aligns the first IRQ number to num.
 */
int spapr_irq_alloc_block(sPAPRMachineState *spapr, int num, bool lsi,
                          bool align, Error **errp)
{
    ICSState *ics = spapr->ics;
    int i, first = -1;

    if (!ics) {
        return -1;
    }

    /*
     * MSIMesage::data is used for storing VIRQ so
     * it has to be aligned to num to support multiple
     * MSI vectors. MSI-X is not affected by this.
     * The hint is used for the first IRQ, the rest should
     * be allocated continuously.
     */
    if (align) {
        assert((num == 1) || (num == 2) || (num == 4) ||
               (num == 8) || (num == 16) || (num == 32));
        first = ics_find_free_block(ics, num, num);
    } else {
        first = ics_find_free_block(ics, num, 1);
    }
    if (first < 0) {
        error_setg(errp, "can't find a free %d-IRQ block", num);
        return -1;
    }

    first += ics->offset;
    for (i = first; i < first + num; ++i) {
        spapr_irq_set_lsi(spapr, i, lsi);
    }

    trace_spapr_irq_alloc_block(first, num, lsi, align);

    return first;
}

void spapr_irq_free(sPAPRMachineState *spapr, int irq, int num)
{
    ICSState *ics = spapr->ics;
    int srcno = irq - ics->offset;
    int i;

    if (ics_valid_irq(ics, irq)) {
        trace_spapr_irq_free(0, irq, num);
        for (i = srcno; i < srcno + num; ++i) {
            if (ICS_IRQ_FREE(ics, i)) {
                trace_spapr_irq_free_warn(0, i + ics->offset);
            }
            memset(&ics->irqs[i], 0, sizeof(ICSIRQState));
        }
    }
}

qemu_irq spapr_qirq(sPAPRMachineState *spapr, int irq)
{
    ICSState *ics = spapr->ics;

    if (ics_valid_irq(ics, irq)) {
        return ics->qirqs[irq - ics->offset];
    }

    return NULL;
}

static void spapr_pic_print_info(InterruptStatsProvider *obj,
                                 Monitor *mon)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(obj);
    CPUState *cs;

    CPU_FOREACH(cs) {
        PowerPCCPU *cpu = POWERPC_CPU(cs);

        icp_pic_print_info(ICP(cpu->intc), mon);
    }

    ics_pic_print_info(spapr->ics, mon);
}

int spapr_get_vcpu_id(PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);

    if (kvm_enabled()) {
        return kvm_arch_vcpu_id(cs);
    } else {
        return cs->cpu_index;
    }
}

void spapr_set_vcpu_id(PowerPCCPU *cpu, int cpu_index, Error **errp)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(qdev_get_machine());
    int vcpu_id;

    vcpu_id = spapr_vcpu_id(spapr, cpu_index);

    if (kvm_enabled() && !kvm_vcpu_id_is_valid(vcpu_id)) {
        error_setg(errp, "Can't create CPU with id %d in KVM", vcpu_id);
        error_append_hint(errp, "Adjust the number of cpus to %d "
                          "or try to raise the number of threads per core\n",
                          vcpu_id * smp_threads / spapr->vsmt);
        return;
    }

    cpu->vcpu_id = vcpu_id;
}

PowerPCCPU *spapr_find_cpu(int vcpu_id)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        PowerPCCPU *cpu = POWERPC_CPU(cs);

        if (spapr_get_vcpu_id(cpu) == vcpu_id) {
            return cpu;
        }
    }

    return NULL;
}

static void spapr_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    sPAPRMachineClass *smc = SPAPR_MACHINE_CLASS(oc);
    FWPathProviderClass *fwc = FW_PATH_PROVIDER_CLASS(oc);
    NMIClass *nc = NMI_CLASS(oc);
    HotplugHandlerClass *hc = HOTPLUG_HANDLER_CLASS(oc);
    PPCVirtualHypervisorClass *vhc = PPC_VIRTUAL_HYPERVISOR_CLASS(oc);
    XICSFabricClass *xic = XICS_FABRIC_CLASS(oc);
    InterruptStatsProviderClass *ispc = INTERRUPT_STATS_PROVIDER_CLASS(oc);

    mc->desc = "pSeries Logical Partition (PAPR compliant)";

    /*
     * We set up the default / latest behaviour here.  The class_init
     * functions for the specific versioned machine types can override
     * these details for backwards compatibility
     */
    mc->init = spapr_machine_init;
    mc->reset = spapr_machine_reset;
    mc->block_default_type = IF_SCSI;
    mc->max_cpus = 1024;
    mc->no_parallel = 1;
    mc->default_boot_order = "";
    mc->default_ram_size = 512 * M_BYTE;
    mc->kvm_type = spapr_kvm_type;
    machine_class_allow_dynamic_sysbus_dev(mc, TYPE_SPAPR_PCI_HOST_BRIDGE);
    mc->pci_allow_0_address = true;
    mc->get_hotplug_handler = spapr_get_hotplug_handler;
    hc->pre_plug = spapr_machine_device_pre_plug;
    hc->plug = spapr_machine_device_plug;
    mc->cpu_index_to_instance_props = spapr_cpu_index_to_props;
    mc->get_default_cpu_node_id = spapr_get_default_cpu_node_id;
    mc->possible_cpu_arch_ids = spapr_possible_cpu_arch_ids;
    hc->unplug_request = spapr_machine_device_unplug_request;

    smc->dr_lmb_enabled = true;
    mc->default_cpu_type = POWERPC_CPU_TYPE_NAME("power8_v2.0");
    mc->has_hotpluggable_cpus = true;
    smc->resize_hpt_default = SPAPR_RESIZE_HPT_ENABLED;
    fwc->get_dev_path = spapr_get_fw_dev_path;
    nc->nmi_monitor_handler = spapr_nmi;
    smc->phb_placement = spapr_phb_placement;
    vhc->hypercall = emulate_spapr_hypercall;
    vhc->hpt_mask = spapr_hpt_mask;
    vhc->map_hptes = spapr_map_hptes;
    vhc->unmap_hptes = spapr_unmap_hptes;
    vhc->store_hpte = spapr_store_hpte;
    vhc->get_patbe = spapr_get_patbe;
    vhc->encode_hpt_for_kvm_pr = spapr_encode_hpt_for_kvm_pr;
    xic->ics_get = spapr_ics_get;
    xic->ics_resend = spapr_ics_resend;
    xic->icp_get = spapr_icp_get;
    ispc->print_info = spapr_pic_print_info;
    /* Force NUMA node memory size to be a multiple of
     * SPAPR_MEMORY_BLOCK_SIZE (256M) since that's the granularity
     * in which LMBs are represented and hot-added
     */
    mc->numa_mem_align_shift = 28;

    smc->default_caps.caps[SPAPR_CAP_HTM] = SPAPR_CAP_OFF;
    smc->default_caps.caps[SPAPR_CAP_VSX] = SPAPR_CAP_ON;
    smc->default_caps.caps[SPAPR_CAP_DFP] = SPAPR_CAP_ON;
    smc->default_caps.caps[SPAPR_CAP_CFPC] = SPAPR_CAP_BROKEN;
    smc->default_caps.caps[SPAPR_CAP_SBBC] = SPAPR_CAP_BROKEN;
    smc->default_caps.caps[SPAPR_CAP_IBS] = SPAPR_CAP_BROKEN;
    spapr_caps_add_properties(smc, &error_abort);
}

static const TypeInfo spapr_machine_info = {
    .name          = TYPE_SPAPR_MACHINE,
    .parent        = TYPE_MACHINE,
    .abstract      = true,
    .instance_size = sizeof(sPAPRMachineState),
    .instance_init = spapr_instance_init,
    .instance_finalize = spapr_machine_finalizefn,
    .class_size    = sizeof(sPAPRMachineClass),
    .class_init    = spapr_machine_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_FW_PATH_PROVIDER },
        { TYPE_NMI },
        { TYPE_HOTPLUG_HANDLER },
        { TYPE_PPC_VIRTUAL_HYPERVISOR },
        { TYPE_XICS_FABRIC },
        { TYPE_INTERRUPT_STATS_PROVIDER },
        { }
    },
};

#define DEFINE_SPAPR_MACHINE(suffix, verstr, latest)                 \
    static void spapr_machine_##suffix##_class_init(ObjectClass *oc, \
                                                    void *data)      \
    {                                                                \
        MachineClass *mc = MACHINE_CLASS(oc);                        \
        spapr_machine_##suffix##_class_options(mc);                  \
        if (latest) {                                                \
            mc->alias = "pseries";                                   \
            mc->is_default = 1;                                      \
        }                                                            \
    }                                                                \
    static void spapr_machine_##suffix##_instance_init(Object *obj)  \
    {                                                                \
        MachineState *machine = MACHINE(obj);                        \
        spapr_machine_##suffix##_instance_options(machine);          \
    }                                                                \
    static const TypeInfo spapr_machine_##suffix##_info = {          \
        .name = MACHINE_TYPE_NAME("pseries-" verstr),                \
        .parent = TYPE_SPAPR_MACHINE,                                \
        .class_init = spapr_machine_##suffix##_class_init,           \
        .instance_init = spapr_machine_##suffix##_instance_init,     \
    };                                                               \
    static void spapr_machine_register_##suffix(void)                \
    {                                                                \
        type_register(&spapr_machine_##suffix##_info);               \
    }                                                                \
    type_init(spapr_machine_register_##suffix)

/*
 * pseries-2.12
 */
static void spapr_machine_2_12_instance_options(MachineState *machine)
{
}

static void spapr_machine_2_12_class_options(MachineClass *mc)
{
    /* Defaults for the latest behaviour inherited from the base class */
}

DEFINE_SPAPR_MACHINE(2_12, "2.12", true);

/*
 * pseries-2.11
 */
#define SPAPR_COMPAT_2_11                                              \
    HW_COMPAT_2_11

static void spapr_machine_2_11_instance_options(MachineState *machine)
{
    spapr_machine_2_12_instance_options(machine);
}

static void spapr_machine_2_11_class_options(MachineClass *mc)
{
    sPAPRMachineClass *smc = SPAPR_MACHINE_CLASS(mc);

    spapr_machine_2_12_class_options(mc);
    smc->default_caps.caps[SPAPR_CAP_HTM] = SPAPR_CAP_ON;
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_11);
}

DEFINE_SPAPR_MACHINE(2_11, "2.11", false);

/*
 * pseries-2.10
 */
#define SPAPR_COMPAT_2_10                                              \
    HW_COMPAT_2_10

static void spapr_machine_2_10_instance_options(MachineState *machine)
{
    spapr_machine_2_11_instance_options(machine);
}

static void spapr_machine_2_10_class_options(MachineClass *mc)
{
    spapr_machine_2_11_class_options(mc);
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_10);
}

DEFINE_SPAPR_MACHINE(2_10, "2.10", false);

/*
 * pseries-2.9
 */
#define SPAPR_COMPAT_2_9                                               \
    HW_COMPAT_2_9                                                      \
    {                                                                  \
        .driver = TYPE_POWERPC_CPU,                                    \
        .property = "pre-2.10-migration",                              \
        .value    = "on",                                              \
    },                                                                 \

static void spapr_machine_2_9_instance_options(MachineState *machine)
{
    spapr_machine_2_10_instance_options(machine);
}

static void spapr_machine_2_9_class_options(MachineClass *mc)
{
    sPAPRMachineClass *smc = SPAPR_MACHINE_CLASS(mc);

    spapr_machine_2_10_class_options(mc);
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_9);
    mc->numa_auto_assign_ram = numa_legacy_auto_assign_ram;
    smc->pre_2_10_has_unused_icps = true;
    smc->resize_hpt_default = SPAPR_RESIZE_HPT_DISABLED;
}

DEFINE_SPAPR_MACHINE(2_9, "2.9", false);

/*
 * pseries-2.8
 */
#define SPAPR_COMPAT_2_8                                        \
    HW_COMPAT_2_8                                               \
    {                                                           \
        .driver   = TYPE_SPAPR_PCI_HOST_BRIDGE,                 \
        .property = "pcie-extended-configuration-space",        \
        .value    = "off",                                      \
    },

static void spapr_machine_2_8_instance_options(MachineState *machine)
{
    spapr_machine_2_9_instance_options(machine);
}

static void spapr_machine_2_8_class_options(MachineClass *mc)
{
    spapr_machine_2_9_class_options(mc);
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_8);
    mc->numa_mem_align_shift = 23;
}

DEFINE_SPAPR_MACHINE(2_8, "2.8", false);

/*
 * pseries-2.7
 */
#define SPAPR_COMPAT_2_7                            \
    HW_COMPAT_2_7                                   \
    {                                               \
        .driver   = TYPE_SPAPR_PCI_HOST_BRIDGE,     \
        .property = "mem_win_size",                 \
        .value    = stringify(SPAPR_PCI_2_7_MMIO_WIN_SIZE),\
    },                                              \
    {                                               \
        .driver   = TYPE_SPAPR_PCI_HOST_BRIDGE,     \
        .property = "mem64_win_size",               \
        .value    = "0",                            \
    },                                              \
    {                                               \
        .driver = TYPE_POWERPC_CPU,                 \
        .property = "pre-2.8-migration",            \
        .value    = "on",                           \
    },                                              \
    {                                               \
        .driver = TYPE_SPAPR_PCI_HOST_BRIDGE,       \
        .property = "pre-2.8-migration",            \
        .value    = "on",                           \
    },

static void phb_placement_2_7(sPAPRMachineState *spapr, uint32_t index,
                              uint64_t *buid, hwaddr *pio,
                              hwaddr *mmio32, hwaddr *mmio64,
                              unsigned n_dma, uint32_t *liobns, Error **errp)
{
    /* Legacy PHB placement for pseries-2.7 and earlier machine types */
    const uint64_t base_buid = 0x800000020000000ULL;
    const hwaddr phb_spacing = 0x1000000000ULL; /* 64 GiB */
    const hwaddr mmio_offset = 0xa0000000; /* 2 GiB + 512 MiB */
    const hwaddr pio_offset = 0x80000000; /* 2 GiB */
    const uint32_t max_index = 255;
    const hwaddr phb0_alignment = 0x10000000000ULL; /* 1 TiB */

    uint64_t ram_top = MACHINE(spapr)->ram_size;
    hwaddr phb0_base, phb_base;
    int i;

    /* Do we have hotpluggable memory? */
    if (MACHINE(spapr)->maxram_size > ram_top) {
        /* Can't just use maxram_size, because there may be an
         * alignment gap between normal and hotpluggable memory
         * regions */
        ram_top = spapr->hotplug_memory.base +
            memory_region_size(&spapr->hotplug_memory.mr);
    }

    phb0_base = QEMU_ALIGN_UP(ram_top, phb0_alignment);

    if (index > max_index) {
        error_setg(errp, "\"index\" for PAPR PHB is too large (max %u)",
                   max_index);
        return;
    }

    *buid = base_buid + index;
    for (i = 0; i < n_dma; ++i) {
        liobns[i] = SPAPR_PCI_LIOBN(index, i);
    }

    phb_base = phb0_base + index * phb_spacing;
    *pio = phb_base + pio_offset;
    *mmio32 = phb_base + mmio_offset;
    /*
     * We don't set the 64-bit MMIO window, relying on the PHB's
     * fallback behaviour of automatically splitting a large "32-bit"
     * window into contiguous 32-bit and 64-bit windows
     */
}

static void spapr_machine_2_7_instance_options(MachineState *machine)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(machine);

    spapr_machine_2_8_instance_options(machine);
    spapr->use_hotplug_event_source = false;
}

static void spapr_machine_2_7_class_options(MachineClass *mc)
{
    sPAPRMachineClass *smc = SPAPR_MACHINE_CLASS(mc);

    spapr_machine_2_8_class_options(mc);
    mc->default_cpu_type = POWERPC_CPU_TYPE_NAME("power7_v2.3");
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_7);
    smc->phb_placement = phb_placement_2_7;
}

DEFINE_SPAPR_MACHINE(2_7, "2.7", false);

/*
 * pseries-2.6
 */
#define SPAPR_COMPAT_2_6 \
    HW_COMPAT_2_6 \
    { \
        .driver   = TYPE_SPAPR_PCI_HOST_BRIDGE,\
        .property = "ddw",\
        .value    = stringify(off),\
    },

static void spapr_machine_2_6_instance_options(MachineState *machine)
{
    spapr_machine_2_7_instance_options(machine);
}

static void spapr_machine_2_6_class_options(MachineClass *mc)
{
    spapr_machine_2_7_class_options(mc);
    mc->has_hotpluggable_cpus = false;
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_6);
}

DEFINE_SPAPR_MACHINE(2_6, "2.6", false);

/*
 * pseries-2.5
 */
#define SPAPR_COMPAT_2_5 \
    HW_COMPAT_2_5 \
    { \
        .driver   = "spapr-vlan", \
        .property = "use-rx-buffer-pools", \
        .value    = "off", \
    },

static void spapr_machine_2_5_instance_options(MachineState *machine)
{
    spapr_machine_2_6_instance_options(machine);
}

static void spapr_machine_2_5_class_options(MachineClass *mc)
{
    sPAPRMachineClass *smc = SPAPR_MACHINE_CLASS(mc);

    spapr_machine_2_6_class_options(mc);
    smc->use_ohci_by_default = true;
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_5);
}

DEFINE_SPAPR_MACHINE(2_5, "2.5", false);

/*
 * pseries-2.4
 */
#define SPAPR_COMPAT_2_4 \
        HW_COMPAT_2_4

static void spapr_machine_2_4_instance_options(MachineState *machine)
{
    spapr_machine_2_5_instance_options(machine);
}

static void spapr_machine_2_4_class_options(MachineClass *mc)
{
    sPAPRMachineClass *smc = SPAPR_MACHINE_CLASS(mc);

    spapr_machine_2_5_class_options(mc);
    smc->dr_lmb_enabled = false;
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_4);
}

DEFINE_SPAPR_MACHINE(2_4, "2.4", false);

/*
 * pseries-2.3
 */
#define SPAPR_COMPAT_2_3 \
        HW_COMPAT_2_3 \
        {\
            .driver   = "spapr-pci-host-bridge",\
            .property = "dynamic-reconfiguration",\
            .value    = "off",\
        },

static void spapr_machine_2_3_instance_options(MachineState *machine)
{
    spapr_machine_2_4_instance_options(machine);
}

static void spapr_machine_2_3_class_options(MachineClass *mc)
{
    spapr_machine_2_4_class_options(mc);
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_3);
}
DEFINE_SPAPR_MACHINE(2_3, "2.3", false);

/*
 * pseries-2.2
 */

#define SPAPR_COMPAT_2_2 \
        HW_COMPAT_2_2 \
        {\
            .driver   = TYPE_SPAPR_PCI_HOST_BRIDGE,\
            .property = "mem_win_size",\
            .value    = "0x20000000",\
        },

static void spapr_machine_2_2_instance_options(MachineState *machine)
{
    spapr_machine_2_3_instance_options(machine);
    machine->suppress_vmdesc = true;
}

static void spapr_machine_2_2_class_options(MachineClass *mc)
{
    spapr_machine_2_3_class_options(mc);
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_2);
}
DEFINE_SPAPR_MACHINE(2_2, "2.2", false);

/*
 * pseries-2.1
 */
#define SPAPR_COMPAT_2_1 \
        HW_COMPAT_2_1

static void spapr_machine_2_1_instance_options(MachineState *machine)
{
    spapr_machine_2_2_instance_options(machine);
}

static void spapr_machine_2_1_class_options(MachineClass *mc)
{
    spapr_machine_2_2_class_options(mc);
    SET_MACHINE_COMPAT(mc, SPAPR_COMPAT_2_1);
}
DEFINE_SPAPR_MACHINE(2_1, "2.1", false);

static void spapr_machine_register_types(void)
{
    type_register_static(&spapr_machine_info);
}

type_init(spapr_machine_register_types)
