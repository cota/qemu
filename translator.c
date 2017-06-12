#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "disas/disas.h"
#include "cpu.h"
#include "tcg.h"
#include "tcg-op.h"
#include "exec/exec-all.h"
#include "exec/translator.h"
#include "exec/gen-icount.h"
#include "exec/log.h"

static inline void check_tcg(const DisasBase *b)
{
    if (tcg_check_temp_count()) {
        error_report("warning: TCG temporary leaks before "TARGET_FMT_lx,
                     b->pc);
    }
}

void translator_gen(const TranslatorOps *ops, DisasBase *b, CPUState *cpu,
                    TranslationBlock *tb)
{
    CPUArchState *env = cpu->env_ptr;
    int max_insns;

    /* Initialize Translator */
    b->tb = tb;
    b->singlestep_enabled = cpu->singlestep_enabled;
    b->pc_first = tb->pc;
    b->pc = b->pc_first;
    b->is_jmp = DISAS_NEXT;
    b->num_insns = 0;
    if (ops->init_context) {
        ops->init_context(b, env);
    }

    /* Initialize globals */
    if (ops->init_globals) {
        ops->init_globals(b, env);
    }
    tcg_clear_temp_count();

    /* Instruction counting */
    max_insns = b->tb->cflags & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
    if (b->singlestep_enabled || singlestep) {
        max_insns = 1;
    }

    /* Start translating */
    gen_tb_start(b->tb);
    if (ops->tb_start) {
        ops->tb_start(b, env);
    }

    while (true) {
        CPUBreakpoint *bp;

        b->num_insns++;
        if (ops->insn_start) {
            ops->insn_start(b, env);
        }

        /* Early exit before breakpoint checks */
        if (unlikely(b->is_jmp != DISAS_NEXT)) {
            break;
        }

        /* Pass breakpoint hits to target for further processing */
        bp = NULL;
        do {
            bp = cpu_breakpoint_get(cpu, b->pc, bp);
            if (unlikely(bp)) {
                BreakpointAction ba = ops->breakpoint_do(b, env, bp);
                if (ba == BREAKPOINT_CONT_INSN) {
                    /* Hit, keep translating */
                    /*
                     * TODO: if we're never going to have more than one BP in a
                     *       single address, we can simply use a bool here.
                     */
                    break;
                } else if (ba == BREAKPOINT_STOP_TB) {
                    goto done_generating;
                }
            }
        } while (bp != NULL);

        /* Accept I/O on last instruction */
        if (b->num_insns == max_insns &&
            (b->tb->cflags & CF_LAST_IO)) {
            gen_io_start();
        }

        /* Disassemble one instruction */
        b->pc = ops->disas_insn(b, env);

        /**************************************************/
        /* Conditions to stop translation                 */
        /**************************************************/

        /* Disassembly already set a stop condition */
        if (b->is_jmp >= DISAS_TARGET) {
            break;
        }

        /* Target-specific conditions */
        b->is_jmp = ops->stop_check(b, env);
        if (b->is_jmp >= DISAS_TARGET) {
            break;
        }

        /* Too many instructions */
        if (tcg_op_buf_full() || b->num_insns >= max_insns) {
            b->is_jmp = DISAS_TOO_MANY;
            break;
        }

        /*
         * Check if next instruction is on next page, which can cause an
         * exception.
         *
         * NOTE: Target-specific code must check a single instruction does not
         *       cross page boundaries; the first in the TB is always allowed to
         *       cross pages (never goes through this check).
         */
        if ((b->pc_first & TARGET_PAGE_MASK)
            != (b->pc & TARGET_PAGE_MASK)) {
            b->is_jmp = DISAS_TOO_MANY;
            break;
        }

        check_tcg(b);
    }

    if (ops->stop) {
        ops->stop(b, env);
    }

    if (b->tb->cflags & CF_LAST_IO) {
        gen_io_end();
    }

 done_generating:
    gen_tb_end(b->tb, b->num_insns);

    check_tcg(b);

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM) &&
        qemu_log_in_addr_range(b->pc_first)) {
        qemu_log_lock();
        qemu_log("----------------\n");
        qemu_log("IN: %s\n", lookup_symbol(b->pc_first));
        log_target_disas(cpu, b->pc_first,
                         b->pc - b->pc_first,
                         ops->disas_flags(b));
        qemu_log("\n");
        qemu_log_unlock();
    }
#endif

    b->tb->size = b->pc - b->pc_first;
    b->tb->icount = b->num_insns;
}
