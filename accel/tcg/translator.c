/*
 * Generic intermediate code generation.
 *
 * Copyright (C) 2016-2017 Lluís Vilanova <vilanova@ac.upc.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "exec/exec-all.h"
#include "exec/gen-icount.h"
#include "exec/log.h"
#include "exec/translator.h"
#include "qemu/plugin.h"

/* Pairs with tcg_clear_temp_count.
   To be called by #TranslatorOps.{translate_insn,tb_stop} if
   (1) the target is sufficiently clean to support reporting,
   (2) as and when all temporaries are known to be consumed.
   For most targets, (2) is at the end of translate_insn.  */
void translator_loop_temp_check(DisasContextBase *db)
{
    if (tcg_check_temp_count()) {
        qemu_log("warning: TCG temporary leaks before "
                 TARGET_FMT_lx "\n", db->pc_next);
    }
}

void translator_loop(const TranslatorOps *ops, DisasContextBase *db,
                     CPUState *cpu, TranslationBlock *tb)
{
    int max_insns;
    bool insn_cb;
    bool tb_trans_cb;
    bool tb_exec_cb;

    /* Initialize DisasContext */
    db->tb = tb;
    db->pc_first = tb->pc;
    db->pc_next = db->pc_first;
    db->is_jmp = DISAS_NEXT;
    db->num_insns = 0;
    db->singlestep_enabled = cpu->singlestep_enabled;

    /* Instruction counting */
    max_insns = tb_cflags(db->tb) & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
    if (db->singlestep_enabled || singlestep) {
        max_insns = 1;
    }

    max_insns = ops->init_disas_context(db, cpu, max_insns);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    /* Reset the temp count so that we can identify leaks */
    tcg_clear_temp_count();

    /* Start translating.  */
    gen_tb_start(db->tb);
    ops->tb_start(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    {
        /* tb->plugin_mask is a u32 */
        unsigned long mask = tb->plugin_mask;

        insn_cb = !!test_bit(QEMU_PLUGIN_EV_VCPU_INSN, &mask);
        tb_trans_cb = !!test_bit(QEMU_PLUGIN_EV_VCPU_TB_TRANS, &mask);
        tb_exec_cb = !!test_bit(QEMU_PLUGIN_EV_VCPU_TB_EXEC, &mask);
    }

    if (insn_cb || tb_trans_cb || tb_exec_cb) {
        tb->plugin_tb = g_new0(struct qemu_plugin_tb, 1);
        QSLIST_INIT(&tb->plugin_tb->arg_list);
    }

#ifdef CONFIG_PLUGINS
    if (tb_exec_cb) {
        TCGv_ptr ptr;

        ptr = tcg_const_ptr(tb->plugin_tb);
        gen_helper_plugin_tb_exec_cb(cpu_env, ptr);
        tcg_temp_free_ptr(ptr);
    }
#endif

    while (true) {
        struct qemu_plugin_insn *insn = insn_cb || tb_trans_cb || tb_exec_cb ?
            g_new0(struct qemu_plugin_insn, 1) : NULL;

#ifdef CONFIG_PLUGINS
        if (insn_cb) {
            TCGv_ptr ptr = tcg_const_ptr(insn);

            gen_helper_plugin_insn_cb(cpu_env, ptr);
            tcg_temp_free_ptr(ptr);
        }
#endif
        db->num_insns++;
        ops->insn_start(db, cpu);
        tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

        /* Pass breakpoint hits to target for further processing */
        if (unlikely(!QTAILQ_EMPTY(&cpu->breakpoints))) {
            CPUBreakpoint *bp;
            QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
                if (bp->pc == db->pc_next) {
                    if (ops->breakpoint_check(db, cpu, bp)) {
                        break;
                    }
                }
            }
            /* The breakpoint_check hook may use DISAS_TOO_MANY to indicate
               that only one more instruction is to be executed.  Otherwise
               it should use DISAS_NORETURN when generating an exception,
               but may use a DISAS_TARGET_* value for Something Else.  */
            if (db->is_jmp > DISAS_TOO_MANY) {
                break;
            }
        }

        /* Disassemble one instruction.  The translate_insn hook should
           update db->pc_next and db->is_jmp to indicate what should be
           done next -- either exiting this loop or locate the start of
           the next instruction.  */
        if (db->num_insns == max_insns && (tb_cflags(db->tb) & CF_LAST_IO)) {
            /* Accept I/O on the last instruction.  */
            gen_io_start();
            ops->translate_insn(db, cpu, insn);
            gen_io_end();
        } else {
            ops->translate_insn(db, cpu, insn);
        }

        if (insn) {
            qemu_plugin_tb_append(tb->plugin_tb, insn);
        }

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            break;
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (tcg_op_buf_full() || db->num_insns >= max_insns) {
            db->is_jmp = DISAS_TOO_MANY;
            break;
        }
    }

    if (tb_trans_cb) {
        qemu_plugin_tb_trans_cb(cpu, tb->plugin_tb);
    }

    /* Emit code to exit the TB, as indicated by db->is_jmp.  */
    ops->tb_stop(db, cpu);
    gen_tb_end(db->tb, db->num_insns);

    /* The disas_log hook may use these values rather than recompute.  */
    db->tb->size = db->pc_next - db->pc_first;
    db->tb->icount = db->num_insns;

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(db->pc_first)) {
        qemu_log_lock();
        qemu_log("----------------\n");
        ops->disas_log(db, cpu);
        qemu_log("\n");
        qemu_log_unlock();
    }
#endif
}
