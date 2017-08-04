/*
 * internal execution defines for qemu
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EXEC_ALL_H
#define EXEC_ALL_H

#include "qemu-common.h"
#include "exec/tb-context.h"

/* allow to see translation results - the slowdown should be negligible, so we leave it */
#define DEBUG_DISAS

/* Page tracking code uses ram addresses in system mode, and virtual
   addresses in userspace mode.  Define tb_page_addr_t to be an appropriate
   type.  */
#if defined(CONFIG_USER_ONLY)
typedef abi_ulong tb_page_addr_t;
#define TB_PAGE_ADDR_FMT TARGET_ABI_FMT_lx
#else
typedef ram_addr_t tb_page_addr_t;
#define TB_PAGE_ADDR_FMT RAM_ADDR_FMT
#endif

#include "qemu/log.h"

void gen_intermediate_code(CPUState *cpu, struct TranslationBlock *tb);
void restore_state_to_opc(CPUArchState *env, struct TranslationBlock *tb,
                          target_ulong *data);

void cpu_gen_init(void);
bool cpu_restore_state(CPUState *cpu, uintptr_t searched_pc);

void QEMU_NORETURN cpu_loop_exit_noexc(CPUState *cpu);
void QEMU_NORETURN cpu_io_recompile(CPUState *cpu, uintptr_t retaddr);
TranslationBlock *tb_gen_code(CPUState *cpu,
                              target_ulong pc, target_ulong cs_base,
                              uint32_t flags,
                              int cflags);

void QEMU_NORETURN cpu_loop_exit(CPUState *cpu);
void QEMU_NORETURN cpu_loop_exit_restore(CPUState *cpu, uintptr_t pc);
void QEMU_NORETURN cpu_loop_exit_atomic(CPUState *cpu, uintptr_t pc);

#if !defined(CONFIG_USER_ONLY)
void cpu_reloading_memory_map(void);
/**
 * cpu_address_space_init:
 * @cpu: CPU to add this address space to
 * @as: address space to add
 * @asidx: integer index of this address space
 *
 * Add the specified address space to the CPU's cpu_ases list.
 * The address space added with @asidx 0 is the one used for the
 * convenience pointer cpu->as.
 * The target-specific code which registers ASes is responsible
 * for defining what semantics address space 0, 1, 2, etc have.
 *
 * Before the first call to this function, the caller must set
 * cpu->num_ases to the total number of address spaces it needs
 * to support.
 *
 * Note that with KVM only one address space is supported.
 */
void cpu_address_space_init(CPUState *cpu, AddressSpace *as, int asidx);
#endif

#if !defined(CONFIG_USER_ONLY) && defined(CONFIG_TCG)
/* cputlb.c */
/**
 * tlb_flush_page:
 * @cpu: CPU whose TLB should be flushed
 * @addr: virtual address of page to be flushed
 *
 * Flush one page from the TLB of the specified CPU, for all
 * MMU indexes.
 */
void tlb_flush_page(CPUState *cpu, target_ulong addr);
/**
 * tlb_flush_page_all_cpus:
 * @cpu: src CPU of the flush
 * @addr: virtual address of page to be flushed
 *
 * Flush one page from the TLB of the specified CPU, for all
 * MMU indexes.
 */
void tlb_flush_page_all_cpus(CPUState *src, target_ulong addr);
/**
 * tlb_flush_page_all_cpus_synced:
 * @cpu: src CPU of the flush
 * @addr: virtual address of page to be flushed
 *
 * Flush one page from the TLB of the specified CPU, for all MMU
 * indexes like tlb_flush_page_all_cpus except the source vCPUs work
 * is scheduled as safe work meaning all flushes will be complete once
 * the source vCPUs safe work is complete. This will depend on when
 * the guests translation ends the TB.
 */
void tlb_flush_page_all_cpus_synced(CPUState *src, target_ulong addr);
/**
 * tlb_flush:
 * @cpu: CPU whose TLB should be flushed
 *
 * Flush the entire TLB for the specified CPU. Most CPU architectures
 * allow the implementation to drop entries from the TLB at any time
 * so this is generally safe. If more selective flushing is required
 * use one of the other functions for efficiency.
 */
void tlb_flush(CPUState *cpu);
/**
 * tlb_flush_all_cpus:
 * @cpu: src CPU of the flush
 */
void tlb_flush_all_cpus(CPUState *src_cpu);
/**
 * tlb_flush_all_cpus_synced:
 * @cpu: src CPU of the flush
 *
 * Like tlb_flush_all_cpus except this except the source vCPUs work is
 * scheduled as safe work meaning all flushes will be complete once
 * the source vCPUs safe work is complete. This will depend on when
 * the guests translation ends the TB.
 */
void tlb_flush_all_cpus_synced(CPUState *src_cpu);
/**
 * tlb_flush_page_by_mmuidx:
 * @cpu: CPU whose TLB should be flushed
 * @addr: virtual address of page to be flushed
 * @idxmap: bitmap of MMU indexes to flush
 *
 * Flush one page from the TLB of the specified CPU, for the specified
 * MMU indexes.
 */
void tlb_flush_page_by_mmuidx(CPUState *cpu, target_ulong addr,
                              uint16_t idxmap);
/**
 * tlb_flush_page_by_mmuidx_all_cpus:
 * @cpu: Originating CPU of the flush
 * @addr: virtual address of page to be flushed
 * @idxmap: bitmap of MMU indexes to flush
 *
 * Flush one page from the TLB of all CPUs, for the specified
 * MMU indexes.
 */
void tlb_flush_page_by_mmuidx_all_cpus(CPUState *cpu, target_ulong addr,
                                       uint16_t idxmap);
/**
 * tlb_flush_page_by_mmuidx_all_cpus_synced:
 * @cpu: Originating CPU of the flush
 * @addr: virtual address of page to be flushed
 * @idxmap: bitmap of MMU indexes to flush
 *
 * Flush one page from the TLB of all CPUs, for the specified MMU
 * indexes like tlb_flush_page_by_mmuidx_all_cpus except the source
 * vCPUs work is scheduled as safe work meaning all flushes will be
 * complete once  the source vCPUs safe work is complete. This will
 * depend on when the guests translation ends the TB.
 */
void tlb_flush_page_by_mmuidx_all_cpus_synced(CPUState *cpu, target_ulong addr,
                                              uint16_t idxmap);
/**
 * tlb_flush_by_mmuidx:
 * @cpu: CPU whose TLB should be flushed
 * @wait: If true ensure synchronisation by exiting the cpu_loop
 * @idxmap: bitmap of MMU indexes to flush
 *
 * Flush all entries from the TLB of the specified CPU, for the specified
 * MMU indexes.
 */
void tlb_flush_by_mmuidx(CPUState *cpu, uint16_t idxmap);
/**
 * tlb_flush_by_mmuidx_all_cpus:
 * @cpu: Originating CPU of the flush
 * @idxmap: bitmap of MMU indexes to flush
 *
 * Flush all entries from all TLBs of all CPUs, for the specified
 * MMU indexes.
 */
void tlb_flush_by_mmuidx_all_cpus(CPUState *cpu, uint16_t idxmap);
/**
 * tlb_flush_by_mmuidx_all_cpus_synced:
 * @cpu: Originating CPU of the flush
 * @idxmap: bitmap of MMU indexes to flush
 *
 * Flush all entries from all TLBs of all CPUs, for the specified
 * MMU indexes like tlb_flush_by_mmuidx_all_cpus except except the source
 * vCPUs work is scheduled as safe work meaning all flushes will be
 * complete once  the source vCPUs safe work is complete. This will
 * depend on when the guests translation ends the TB.
 */
void tlb_flush_by_mmuidx_all_cpus_synced(CPUState *cpu, uint16_t idxmap);
/**
 * tlb_set_page_with_attrs:
 * @cpu: CPU to add this TLB entry for
 * @vaddr: virtual address of page to add entry for
 * @paddr: physical address of the page
 * @attrs: memory transaction attributes
 * @prot: access permissions (PAGE_READ/PAGE_WRITE/PAGE_EXEC bits)
 * @mmu_idx: MMU index to insert TLB entry for
 * @size: size of the page in bytes
 *
 * Add an entry to this CPU's TLB (a mapping from virtual address
 * @vaddr to physical address @paddr) with the specified memory
 * transaction attributes. This is generally called by the target CPU
 * specific code after it has been called through the tlb_fill()
 * entry point and performed a successful page table walk to find
 * the physical address and attributes for the virtual address
 * which provoked the TLB miss.
 *
 * At most one entry for a given virtual address is permitted. Only a
 * single TARGET_PAGE_SIZE region is mapped; the supplied @size is only
 * used by tlb_flush_page.
 */
void tlb_set_page_with_attrs(CPUState *cpu, target_ulong vaddr,
                             hwaddr paddr, MemTxAttrs attrs,
                             int prot, int mmu_idx, target_ulong size);
/* tlb_set_page:
 *
 * This function is equivalent to calling tlb_set_page_with_attrs()
 * with an @attrs argument of MEMTXATTRS_UNSPECIFIED. It's provided
 * as a convenience for CPUs which don't use memory transaction attributes.
 */
void tlb_set_page(CPUState *cpu, target_ulong vaddr,
                  hwaddr paddr, int prot,
                  int mmu_idx, target_ulong size);
void tb_invalidate_phys_addr(AddressSpace *as, hwaddr addr);
void probe_write(CPUArchState *env, target_ulong addr, int mmu_idx,
                 uintptr_t retaddr);
#else
static inline void tlb_flush_page(CPUState *cpu, target_ulong addr)
{
}
static inline void tlb_flush_page_all_cpus(CPUState *src, target_ulong addr)
{
}
static inline void tlb_flush_page_all_cpus_synced(CPUState *src,
                                                  target_ulong addr)
{
}
static inline void tlb_flush(CPUState *cpu)
{
}
static inline void tlb_flush_all_cpus(CPUState *src_cpu)
{
}
static inline void tlb_flush_all_cpus_synced(CPUState *src_cpu)
{
}
static inline void tlb_flush_page_by_mmuidx(CPUState *cpu,
                                            target_ulong addr, uint16_t idxmap)
{
}

static inline void tlb_flush_by_mmuidx(CPUState *cpu, uint16_t idxmap)
{
}
static inline void tlb_flush_page_by_mmuidx_all_cpus(CPUState *cpu,
                                                     target_ulong addr,
                                                     uint16_t idxmap)
{
}
static inline void tlb_flush_page_by_mmuidx_all_cpus_synced(CPUState *cpu,
                                                            target_ulong addr,
                                                            uint16_t idxmap)
{
}
static inline void tlb_flush_by_mmuidx_all_cpus(CPUState *cpu, uint16_t idxmap)
{
}
static inline void tlb_flush_by_mmuidx_all_cpus_synced(CPUState *cpu,
                                                       uint16_t idxmap)
{
}
static inline void tb_invalidate_phys_addr(AddressSpace *as, hwaddr addr)
{
}
#endif

#define CODE_GEN_ALIGN           16 /* must be >= of the size of a icache line */

/* Estimated block size for TB allocation.  */
/* ??? The following is based on a 2015 survey of x86_64 host output.
   Better would seem to be some sort of dynamically sized TB array,
   adapting to the block sizes actually being produced.  */
#if defined(CONFIG_SOFTMMU)
#define CODE_GEN_AVG_BLOCK_SIZE 400
#else
#define CODE_GEN_AVG_BLOCK_SIZE 150
#endif

#if defined(_ARCH_PPC) \
    || defined(__x86_64__) || defined(__i386__) \
    || defined(__sparc__) || defined(__aarch64__) \
    || defined(__s390x__) || defined(__mips__) \
    || defined(CONFIG_TCG_INTERPRETER)
/* NOTE: Direct jump patching must be atomic to be thread-safe. */
#define USE_DIRECT_JUMP
#endif

/*
 * Translation Cache-related fields of a TB.
 * This struct exists just for convenience; we keep track of TB's in a binary
 * search tree, and the only fields needed to compare TB's in the tree are
 * @ptr and @size. @search is brought here for consistency, since it is also
 * a TC-related field.
 */
struct tb_tc {
    void *ptr;    /* pointer to the translated code */
    uint8_t *search;  /* pointer to search data */
    size_t size;
};

struct TranslationBlock {
    target_ulong pc;   /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint32_t flags; /* flags defining in which context the code was generated */
    uint16_t size;      /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    uint16_t icount;
    uint32_t cflags;    /* compile flags */
#define CF_COUNT_MASK  0x7fff
#define CF_LAST_IO     0x8000 /* Last insn may be an IO access.  */
#define CF_NOCACHE     0x10000 /* To be freed after execution */
#define CF_USE_ICOUNT  0x20000
#define CF_IGNORE_ICOUNT 0x40000 /* Do not generate icount code */
#define CF_INVALID     0x80000 /* TB is stale. Protected by tb->jmp_lock */
#define CF_PARALLEL    0x100000 /* Generate code for a parallel context */
/* cflags' mask for hashing/comparison */
#define CF_HASH_MASK (CF_COUNT_MASK | CF_PARALLEL)

    /* Per-vCPU dynamic tracing state used to generate this TB */
    uint32_t trace_vcpu_dstate;

    struct tb_tc tc;

    /* original tb when cflags has CF_NOCACHE */
    struct TranslationBlock *orig_tb;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[].
       The list is protected by the TB's page('s) lock(s) */
    uintptr_t page_next[2];
    tb_page_addr_t page_addr[2];

    /* The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continues its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */
#define TB_JMP_RESET_OFFSET_INVALID 0xffff /* indicates no jump generated */
#ifdef USE_DIRECT_JUMP
    uint16_t jmp_insn_offset[2]; /* offset of native jump instruction */
#else
    uintptr_t jmp_target_addr[2]; /* target address for indirect jump */
#endif
    /*
     * Each TB has a NULL-terminated list (jmp_list_head) of incoming jumps.
     * Each TB can have two outgoing jumps, and therefore can participate
     * in two lists. The list entries are kept in jmp_list_next[2]. The least
     * significant bit (LSB) of the pointers in these lists is used to encode
     * which of the two list entries is to be used in the pointed TB.
     *
     * List traversals are protected by jmp_lock. The destination TB of each
     * outgoing jump is kept in jmp_dest[] so that the appropriate jmp_lock
     * can be acquired from any origin TB.
     *
     * jmp_dest[] are tagged pointers as well. The LSB is set when the TB is
     * being invalidated, so that no further outgoing jumps from it can be set.
     *
     * jmp_lock also protects the CF_INVALID cflag; a jump must not be chained
     * to a destination TB that has CF_INVALID set.
     */
    uintptr_t jmp_list_head;
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_dest[2];
    QemuSpin jmp_lock;
};

extern bool parallel_cpus;

/* Hide the atomic_read to make code a little easier on the eyes */
static inline uint32_t tb_cflags(const TranslationBlock *tb)
{
    return atomic_read(&tb->cflags);
}

/* current cflags for hashing/comparison */
static inline uint32_t curr_cflags(void)
{
    return parallel_cpus ? CF_PARALLEL : 0;
}

void tb_flush(CPUState *cpu);
void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);
TranslationBlock *tb_htable_lookup(CPUState *cpu, target_ulong pc,
                                   target_ulong cs_base, uint32_t flags,
                                   uint32_t cf_mask);

#if defined(USE_DIRECT_JUMP)

#if defined(CONFIG_TCG_INTERPRETER)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    atomic_set((int32_t *)jmp_addr, addr - (jmp_addr + 4));
    /* no need to flush icache explicitly */
}
#elif defined(_ARCH_PPC)
void ppc_tb_set_jmp_target(uintptr_t jmp_addr, uintptr_t addr);
#define tb_set_jmp_target1 ppc_tb_set_jmp_target
#elif defined(__i386__) || defined(__x86_64__)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    atomic_set((int32_t *)jmp_addr, addr - (jmp_addr + 4));
    /* no need to flush icache explicitly */
}
#elif defined(__s390x__)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    intptr_t disp = addr - (jmp_addr - 2);
    atomic_set((int32_t *)jmp_addr, disp / 2);
    /* no need to flush icache explicitly */
}
#elif defined(__aarch64__)
void aarch64_tb_set_jmp_target(uintptr_t jmp_addr, uintptr_t addr);
#define tb_set_jmp_target1 aarch64_tb_set_jmp_target
#elif defined(__sparc__) || defined(__mips__)
void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr);
#else
#error tb_set_jmp_target1 is missing
#endif

static inline void tb_set_jmp_target(TranslationBlock *tb,
                                     int n, uintptr_t addr)
{
    uint16_t offset = tb->jmp_insn_offset[n];
    tb_set_jmp_target1((uintptr_t)(tb->tc.ptr + offset), addr);
}

#else

/* set the jump target */
static inline void tb_set_jmp_target(TranslationBlock *tb,
                                     int n, uintptr_t addr)
{
    tb->jmp_target_addr[n] = addr;
}

#endif

static inline void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next)
{
    uintptr_t old;

    qemu_spin_lock(&tb_next->jmp_lock);

    /* make sure the destination TB is valid */
    if (tb_next->cflags & CF_INVALID) {
        goto out_unlock_next;
    }
    /*
     * Atomically claim the jump destination slot only if it was NULL.
     * This implies a full barrier that pairs with the write barrier before
     * setting jmp_dest[n] to NULL in tb_jmp_unlink, thereby guaranteeing that
     * we see jmp_target/addr in a consistent state.
     */
    old = atomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t)NULL, (uintptr_t)tb_next);
    if (old) {
        goto out_unlock_next;
    }

    /* patch the native jump address */
    tb_set_jmp_target(tb, n, (uintptr_t)tb_next->tc.ptr);

    /* add in TB jmp list */
    tb->jmp_list_next[n] = tb_next->jmp_list_head;
    tb_next->jmp_list_head = (uintptr_t)tb | n;

    qemu_spin_unlock(&tb_next->jmp_lock);

    qemu_log_mask_and_addr(CPU_LOG_EXEC, tb->pc,
                           "Linking TBs %p [" TARGET_FMT_lx
                           "] index %d -> %p [" TARGET_FMT_lx "]\n",
                           tb->tc.ptr, tb->pc, n,
                           tb_next->tc.ptr, tb_next->pc);
    return;

 out_unlock_next:
    qemu_spin_unlock(&tb_next->jmp_lock);
    return;
}

/* GETPC is the true target of the return instruction that we'll execute.  */
#if defined(CONFIG_TCG_INTERPRETER)
extern uintptr_t tci_tb_ptr;
# define GETPC() tci_tb_ptr
#else
# define GETPC() \
    ((uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0)))
#endif

/* The true return address will often point to a host insn that is part of
   the next translated guest insn.  Adjust the address backward to point to
   the middle of the call insn.  Subtracting one would do the job except for
   several compressed mode architectures (arm, mips) which set the low bit
   to indicate the compressed mode; subtracting two works around that.  It
   is also the case that there are no host isas that contain a call insn
   smaller than 4 bytes, so we don't worry about special-casing this.  */
#define GETPC_ADJ   2

#if !defined(CONFIG_USER_ONLY)

struct MemoryRegion *iotlb_to_region(CPUState *cpu,
                                     hwaddr index, MemTxAttrs attrs);

void tlb_fill(CPUState *cpu, target_ulong addr, MMUAccessType access_type,
              int mmu_idx, uintptr_t retaddr);

#endif

#if defined(CONFIG_USER_ONLY)
void mmap_lock(void);
void mmap_unlock(void);
bool have_mmap_lock(void);

static inline tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr)
{
    return addr;
}
#else
static inline void mmap_lock(void) {}
static inline void mmap_unlock(void) {}

/* cputlb.c */
tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr);

void tlb_reset_dirty(CPUState *cpu, ram_addr_t start1, ram_addr_t length);
void tlb_set_dirty(CPUState *cpu, target_ulong vaddr);

/* exec.c */
void tb_flush_jmp_cache(CPUState *cpu, target_ulong addr);

MemoryRegionSection *
address_space_translate_for_iotlb(CPUState *cpu, int asidx, hwaddr addr,
                                  hwaddr *xlat, hwaddr *plen);
hwaddr memory_region_section_get_iotlb(CPUState *cpu,
                                       MemoryRegionSection *section,
                                       target_ulong vaddr,
                                       hwaddr paddr, hwaddr xlat,
                                       int prot,
                                       target_ulong *address);
bool memory_region_is_unassigned(MemoryRegion *mr);

#endif

/* vl.c */
extern int singlestep;

#endif
