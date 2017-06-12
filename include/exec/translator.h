#ifndef EXEC_TRANSLATOR_H
#define EXEC_TRANSLATOR_H

#include "exec/exec-all.h"
#include "tcg.h"

/**
 * TrBreakpointAction:
 * @BREAKPOINT_DO_NOTHING: Do nothing / no hit
 * @BREAKPOINT_CONT_INSN: Continue translating instruction
 * @BREAKPOINT_STOP_TB: Stop translating TB
 *
 *  Translator Breakpoint Action.
 */
typedef enum BreakpointAction {
    BREAKPOINT_DO_NOTHING,
    BREAKPOINT_CONT_INSN,
    BREAKPOINT_STOP_TB,
} BreakpointAction;

/**
 * DisasBase - architecture-agnostic disassembly context.
 * @tb: Translation block.
 * @pc_first: Address of first guest instruction in this TB.
 * @pc: Address of next guest instruction in this TB (current during
 *      disassembly).
 * @is_jmp: Whether to jump in the translation -- and if so, how.
 * @num_insns: Number of translated instructions (including current).
 * @singlestep_enabled: "Hardware" single stepping enabled.
 */
typedef struct DisasBase {
    TranslationBlock *tb;
    target_ulong pc_first;
    target_ulong pc;
    int is_jmp;
    unsigned int num_insns;
    bool singlestep_enabled;
} DisasBase;

/* all void-returning ops are optional, i.e. can be NULL */
typedef struct TranslatorOps {
    void (*init_context)(DisasBase *, CPUArchState *);
    void (*init_globals)(DisasBase *, CPUArchState *);
    void (*tb_start)(DisasBase *, CPUArchState *);
    void (*insn_start)(DisasBase *, CPUArchState *);
    BreakpointAction (*breakpoint_do)(DisasBase *, CPUArchState *,
                                      const CPUBreakpoint *);
    target_ulong (*disas_insn)(DisasBase *, CPUArchState *);
    int (*stop_check)(DisasBase *, CPUArchState *);
    void (*stop)(DisasBase *, CPUArchState *);
    int (*disas_flags)(const DisasBase *);
} TranslatorOps;

void translator_gen(const TranslatorOps *ops, DisasBase *b, CPUState *cpu,
                    TranslationBlock *tb);

#endif /* EXEC_TRANSLATOR_H */
