/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_PLUGIN_H
#define QEMU_PLUGIN_H

#include "qemu/config-file.h"
#include "qemu/plugin-api.h"
#include "qemu/error-report.h"
#include "qemu/queue.h"
#include "qemu/option.h"

/*
 * Option parsing/processing.
 * Note that we can load an arbitrary number of plugins.
 */
struct qemu_plugin_desc;
QTAILQ_HEAD(qemu_plugin_list, qemu_plugin_desc);

#ifdef CONFIG_PLUGINS
extern QemuOptsList qemu_plugin_opts;

static inline void qemu_plugin_add_opts(void)
{
    qemu_add_opts(&qemu_plugin_opts);
}

void qemu_plugin_opt_parse(const char *optarg, struct qemu_plugin_list *head);
int qemu_plugin_load_list(struct qemu_plugin_list *head);
#else /* !CONFIG_PLUGINS */
static inline void qemu_plugin_add_opts(void)
{ }

static inline void qemu_plugin_opt_parse(const char *optarg,
                                         struct qemu_plugin_list *head)
{
    error_report("plugin interface not enabled in this build");
    exit(1);
}

static inline int qemu_plugin_load_list(struct qemu_plugin_list *head)
{
    return 0;
}
#endif /* !CONFIG_PLUGINS */

/*
 * Events that plugins can subscribe to.
 */
enum qemu_plugin_event {
    QEMU_PLUGIN_EV_VCPU_INIT,
    QEMU_PLUGIN_EV_VCPU_EXIT,
    QEMU_PLUGIN_EV_VCPU_MEM,
    QEMU_PLUGIN_EV_VCPU_TB_TRANS,
    QEMU_PLUGIN_EV_VCPU_IDLE,
    QEMU_PLUGIN_EV_VCPU_RESUME,
    QEMU_PLUGIN_EV_VCPU_SYSCALL,
    QEMU_PLUGIN_EV_VCPU_SYSCALL_RET,
    QEMU_PLUGIN_EV_FLUSH,
    QEMU_PLUGIN_EV_MAX,
};

struct qemu_plugin_dyn_cb_head;

struct qemu_plugin_insn {
    void *data;
    size_t size;
    size_t capacity;
    struct qemu_plugin_dyn_cb_head *cb_list;
    uint64_t vaddr;
};

struct qemu_plugin_tb {
    struct qemu_plugin_insn *insns;
    size_t n;
    size_t capacity;
    struct qemu_plugin_dyn_cb_head *cb_list;
    uint64_t vaddr;
};

static inline void qemu_plugin_insn_append(struct qemu_plugin_insn *insn,
                                           const void *from, size_t size)
{
    if (unlikely(insn->size + size > insn->capacity)) {
        insn->data = g_realloc(insn->data, insn->size + size);
        insn->capacity = insn->size + size;
    }
    memcpy(insn->data + insn->size, from, size);
    insn->size += size;
}

static inline
struct qemu_plugin_insn *qemu_plugin_tb_insn_get(struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;

    if (unlikely(tb->n == tb->capacity)) {
        tb->insns = g_renew(struct qemu_plugin_insn, tb->insns, ++tb->capacity);
        insn = &tb->insns[tb->capacity - 1];
        insn->data = NULL;
        insn->capacity = 0;
    }
    insn = &tb->insns[tb->n++];
    insn->cb_list = NULL;
    insn->size = 0;
    return insn;
}

#ifdef CONFIG_PLUGINS

void qemu_plugin_vcpu_init_hook(CPUState *cpu);
void qemu_plugin_vcpu_exit_hook(CPUState *cpu);
void qemu_plugin_tb_trans_cb(CPUState *cpu, struct qemu_plugin_tb *tb);
void qemu_plugin_vcpu_idle_cb(CPUState *cpu);
void qemu_plugin_vcpu_resume_cb(CPUState *cpu);
void qemu_plugin_vcpu_mem_exec_cb(CPUState *cpu, uint64_t vaddr,
                                  uint8_t size_shift, bool store);
void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1,
                         uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8);
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret);

void qemu_plugin_flush_cb(void);

#else /* !CONFIG_PLUGINS */

static inline void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_tb_trans_cb(CPUState *cpu,
                                           struct qemu_plugin_tb *tb)
{ }

static inline void qemu_plugin_vcpu_idle_cb(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_resume_cb(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_mem_exec_cb(CPUState *cpu, uint64_t vaddr,
                                                uint8_t size_shift, bool store)
{ }

static inline void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                         uint64_t a7, uint64_t a8)
{ }

static inline
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret)
{ }

static inline void qemu_plugin_flush_cb(void)
{ }

#endif /* !CONFIG_PLUGINS */

#endif /* QEMU_PLUGIN_H */
