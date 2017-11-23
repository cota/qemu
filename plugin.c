/* plugin.c - QEMU Plugin interface
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/plugin.h"
#include "qemu/config-file.h"
#include "qapi/error.h"
#include "qemu/option.h"
#include "qemu/rcu_queue.h"
#include "qemu/rcu.h"
#include "qom/cpu.h"
#include "exec/cpu-common.h"
#include <dlfcn.h>

#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "qemu/plugin.h"
#include "sysemu/sysemu.h"
#include "tcg/tcg.h"

union qemu_plugin_cb_sig {
    qemu_plugin_simple_cb_t          simple;
    qemu_plugin_vcpu_simple_cb_t     vcpu_simple;
    qemu_plugin_vcpu_insn_cb_t       vcpu_insn;
    qemu_plugin_vcpu_tb_exec_cb_t    vcpu_tb_exec;
    qemu_plugin_vcpu_tb_trans_cb_t   vcpu_tb_trans;
    qemu_plugin_vcpu_mem_cb_t        vcpu_mem;
    qemu_plugin_vcpu_syscall_cb_t    vcpu_syscall;
    qemu_plugin_vcpu_syscall_ret_cb_t vcpu_syscall_ret;
    void *generic;
};

struct qemu_plugin_cb {
    struct qemu_plugin_ctx *ctx;
    union qemu_plugin_cb_sig f;
    QLIST_ENTRY(qemu_plugin_cb) entry;
};

QLIST_HEAD(qemu_plugin_cb_head, qemu_plugin_cb);

struct qemu_plugin_ctx {
    /* @rcu: keep at the top to help valgrind find the whole struct */
    struct rcu_head rcu;
    void *handle; /* dlopen */
    qemu_plugin_id_t id;
    struct qemu_plugin_cb *callbacks[QEMU_PLUGIN_EV_MAX];
    QTAILQ_ENTRY(qemu_plugin_ctx) entry;
    qemu_plugin_uninstall_cb_t uninstall_cb;
    bool uninstalling; /* protected by plugin.lock */
};

/* global state */
struct qemu_plugin_state {
    QTAILQ_HEAD(, qemu_plugin_ctx) ctxs;
    QLIST_HEAD(, qemu_plugin_cb) cb_lists[QEMU_PLUGIN_EV_MAX];
    /*
     * Use the HT as a hash map by inserting k == v, which saves memory as
     * documented by GLib. The parent struct is obtained with container_of().
     */
    GHashTable *id_ht;
    /*
     * Use the HT as a hash map. Note that we could use a list here,
     * but with the HT we avoid adding a field to CPUState.
     */
    GHashTable *cpu_ht;
    DECLARE_BITMAP(mask, QEMU_PLUGIN_EV_MAX);
    /*
     * @lock protects the struct as well as ctx->uninstalling.
     * The lock must be acquired by all API ops.
     * The lock is recursive, which greatly simplifies things, e.g.
     * callback registration from qemu_plugin_vcpu_for_each().
     */
    QemuRecMutex lock;
};

/*
 * For convenience we use a bitmap for plugin.mask, but really all we need is a
 * u32, which is what we store in TranslationBlock.
 */
QEMU_BUILD_BUG_ON(QEMU_PLUGIN_EV_MAX > 32);

struct qemu_plugin_desc {
    char *path;
    char **argv;
    QTAILQ_ENTRY(qemu_plugin_desc) entry;
    int argc;
};

struct qemu_plugin_parse_arg {
    struct qemu_plugin_list *head;
    struct qemu_plugin_desc *curr;
};

QemuOptsList qemu_plugin_opts = {
    .name = "plugin",
    .implied_opt_name = "file",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_plugin_opts.head),
    .desc = {
        /* do our own parsing to support multiple plugins */
        { /* end of list */ }
    },
};

typedef int (*qemu_plugin_install_func_t)(qemu_plugin_id_t, int, char **);

static struct qemu_plugin_state plugin;

static struct qemu_plugin_desc *plugin_find_desc(struct qemu_plugin_list *head,
                                                 const char *path)
{
    struct qemu_plugin_desc *desc;

    QTAILQ_FOREACH(desc, head, entry) {
        if (strcmp(desc->path, path) == 0) {
            return desc;
        }
    }
    return NULL;
}

static int plugin_add(void *opaque, const char *name, const char *value,
                      Error **errp)
{
    struct qemu_plugin_parse_arg *arg = opaque;
    struct qemu_plugin_desc *p;

    if (strcmp(name, "file") == 0) {
        if (strcmp(value, "") == 0) {
            error_setg(errp, "requires a non-empty argument");
            return 1;
        }
        p = plugin_find_desc(arg->head, value);
        if (p == NULL) {
            p = g_new0(struct qemu_plugin_desc, 1);
            p->path = g_strdup(value);
            QTAILQ_INSERT_TAIL(arg->head, p, entry);
        }
        arg->curr = p;
    } else if (strcmp(name, "arg") == 0) {
        if (arg->curr == NULL) {
            error_setg(errp, "missing earlier '-plugin file=' option");
            return 1;
        }
        p = arg->curr;
        p->argc++;
        p->argv = g_realloc_n(p->argv, p->argc, sizeof(char *));
        p->argv[p->argc - 1] = g_strdup(value);
    } else {
        g_assert_not_reached();
    }
    return 0;
}

void qemu_plugin_opt_parse(const char *optarg, struct qemu_plugin_list *head)
{
    struct qemu_plugin_parse_arg arg;
    QemuOpts *opts;

    opts = qemu_opts_parse_noisily(qemu_find_opts("plugin"), optarg, true);
    if (opts == NULL) {
        exit(1);
    }
    arg.head = head;
    arg.curr = NULL;
    qemu_opt_foreach(opts, plugin_add, &arg, &error_fatal);
    qemu_opts_del(opts);
}

/*
 * From: https://en.wikipedia.org/wiki/Xorshift
 * This is faster than rand_r(), and gives us a wider range (RAND_MAX is only
 * guaranteed to be >= INT_MAX).
 */
static uint64_t xorshift64star(uint64_t x)
{
    x ^= x >> 12; /* a */
    x ^= x << 25; /* b */
    x ^= x >> 27; /* c */
    return x * UINT64_C(2685821657736338717);
}

static int plugin_load(struct qemu_plugin_desc *desc)
{
    qemu_plugin_install_func_t install;
    struct qemu_plugin_ctx *ctx;
    char *err;
    int rc;

    ctx = qemu_memalign(qemu_dcache_linesize, sizeof(*ctx));
    memset(ctx, 0, sizeof(*ctx));
    ctx->handle = dlopen(desc->path, RTLD_NOW);
    if (ctx->handle == NULL) {
        error_report("%s: %s", __func__, dlerror());
        goto err_dlopen;
    }

    /* clear any previous dlerror, call dlsym, then check dlerror */
    dlerror();
    install = dlsym(ctx->handle, "qemu_plugin_install");
    err = dlerror();
    if (err) {
        error_report("%s: %s", __func__, err);
        goto err_symbol;
    }
    /* symbol was found; it could be NULL though */
    if (install == NULL) {
        error_report("%s: %s: qemu_plugin_install is NULL",
                     __func__, desc->path);
        goto err_symbol;
    }

    qemu_rec_mutex_lock(&plugin.lock);

    /* find an unused random id with &ctx as the seed */
    ctx->id = (uint64_t)ctx;
    for (;;) {
        void *existing;

        ctx->id = xorshift64star(ctx->id);
        existing = g_hash_table_lookup(plugin.id_ht, &ctx->id);
        if (likely(existing == NULL)) {
            bool success;

            success = g_hash_table_insert(plugin.id_ht, &ctx->id, &ctx->id);
            g_assert(success);
            break;
        }
    }
    QTAILQ_INSERT_TAIL(&plugin.ctxs, ctx, entry);
    qemu_rec_mutex_unlock(&plugin.lock);

    rc = install(ctx->id, desc->argc, desc->argv);
    if (rc) {
        error_report("%s: qemu_plugin_install returned error code %d",
                     __func__, rc);
        /*
         * we cannot rely on the plugin doing its own cleanup, so
         * call a full uninstall if the plugin did not already call it.
         */
        qemu_rec_mutex_lock(&plugin.lock);
        if (!ctx->uninstalling) {
            qemu_plugin_uninstall(ctx->id, NULL);
        }
        qemu_rec_mutex_unlock(&plugin.lock);
        return 1;
    }
    return 0;

 err_symbol:
    if (dlclose(ctx->handle)) {
        warn_report("%s: %s", __func__, dlerror());
    }
 err_dlopen:
    qemu_vfree(ctx);
    return 1;
}

/* call after having removed @desc from the list */
static void plugin_desc_free(struct qemu_plugin_desc *desc)
{
    int i;

    for (i = 0; i < desc->argc; i++) {
        g_free(desc->argv[i]);
    }
    g_free(desc->argv);
    g_free(desc->path);
    g_free(desc);
}

/**
 * qemu_plugin_load_list - load a list of plugins
 * @head: head of the list of descriptors of the plugins to be loaded
 *
 * Returns 0 if all plugins in the list are installed, !0 otherwise.
 *
 * Note: the descriptor of each successfully installed plugin is removed
 * from the list given by @head and then freed.
 */
int qemu_plugin_load_list(struct qemu_plugin_list *head)
{
    struct qemu_plugin_desc *desc, *next;

    QTAILQ_FOREACH_SAFE(desc, head, entry, next) {
        int err;

        err = plugin_load(desc);
        if (err) {
            return err;
        }
        QTAILQ_REMOVE(head, desc, entry);
        plugin_desc_free(desc);
    }
    return 0;
}

static struct qemu_plugin_ctx *id_to_ctx__locked(qemu_plugin_id_t id)
{
    struct qemu_plugin_ctx *ctx;
    qemu_plugin_id_t *id_p;

    id_p = g_hash_table_lookup(plugin.id_ht, &id);
    ctx = container_of(id_p, struct qemu_plugin_ctx, id);
    if (ctx == NULL) {
        error_report("plugin: invalid plugin id %" PRIu64, id);
        abort();
    }
    return ctx;
}

static void plugin_cpu_update__async(CPUState *cpu, run_on_cpu_data data)
{
    bitmap_copy(cpu->plugin_mask, &data.host_ulong, QEMU_PLUGIN_EV_MAX);
    cpu_tb_jmp_cache_clear(cpu);
}

static void plugin_cpu_update__locked(gpointer k, gpointer v, gpointer udata)
{
    CPUState *cpu = container_of(k, CPUState, cpu_index);
    run_on_cpu_data mask = RUN_ON_CPU_HOST_ULONG(*plugin.mask);

    if (cpu->created) {
        async_run_on_cpu(cpu, plugin_cpu_update__async, mask);
    } else {
        plugin_cpu_update__async(cpu, mask);
    }
}

static void plugin_unregister_cb__locked(struct qemu_plugin_ctx *ctx,
                                         enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb = ctx->callbacks[ev];

    if (cb == NULL) {
        return;
    }
    QLIST_REMOVE_RCU(cb, entry);
    g_free(cb);
    ctx->callbacks[ev] = NULL;
    if (QLIST_EMPTY_RCU(&plugin.cb_lists[ev])) {
        clear_bit(ev, plugin.mask);
        g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update__locked, NULL);
    }
}

static void plugin_destroy__rcuthread(struct qemu_plugin_ctx *ctx)
{
    bool success;

    qemu_rec_mutex_lock(&plugin.lock);
    g_assert(ctx->uninstalling);
    success = g_hash_table_remove(plugin.id_ht, &ctx->id);
    g_assert(success);

    QTAILQ_REMOVE(&plugin.ctxs, ctx, entry);
    qemu_rec_mutex_unlock(&plugin.lock);

    if (ctx->uninstall_cb) {
        ctx->uninstall_cb(ctx->id);
    }
    if (dlclose(ctx->handle)) {
        warn_report("%s: %s", __func__, dlerror());
    }
    qemu_vfree(ctx);
}

void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_uninstall_cb_t cb)
{
    struct qemu_plugin_ctx *ctx;
    enum qemu_plugin_event ev;

    qemu_rec_mutex_lock(&plugin.lock);
    ctx = id_to_ctx__locked(id);
    if (unlikely(ctx->uninstalling)) {
        error_report("plugin: called %s more than once", __func__);
        abort();
    }
    ctx->uninstalling = true;
    ctx->uninstall_cb = cb;
    /*
     * Unregister all callbacks. This is an RCU list so it is possible that some
     * callbacks will still be called in this RCU grace period. For this reason
     * we cannot yet uninstall the plugin.
     */
    for (ev = 0; ev < QEMU_PLUGIN_EV_MAX; ev++) {
        plugin_unregister_cb__locked(ctx, ev);
    }
    qemu_rec_mutex_unlock(&plugin.lock);

    /* TODO: kick all vCPUs to make sure the RCU grace period completes ASAP */
    call_rcu(ctx, plugin_destroy__rcuthread, rcu);
}

static void plugin_vcpu_cb__simple(CPUState *cpu, enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_VCPU_INIT:
    case QEMU_PLUGIN_EV_VCPU_EXIT:
    case QEMU_PLUGIN_EV_VCPU_IDLE:
    case QEMU_PLUGIN_EV_VCPU_RESUME:
        /* iterate safely; plugins might uninstall themselves at any time */
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_vcpu_simple_cb_t func = cb->f.vcpu_simple;

            func(cb->ctx->id, cpu->cpu_index);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static void plugin_cb__simple(enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_FLUSH:
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_simple_cb_t func = cb->f.simple;

            func(cb->ctx->id);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static void plugin_register_cb(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                               void *func)
{
    struct qemu_plugin_ctx *ctx;

    qemu_rec_mutex_lock(&plugin.lock);
    ctx = id_to_ctx__locked(id);
    /* if the plugin is on its way out, ignore this request */
    if (unlikely(ctx->uninstalling)) {
        goto out_unlock;
    }
    if (func) {
        struct qemu_plugin_cb *cb = ctx->callbacks[ev];

        if (cb) {
            cb->f.generic = func;
        } else {
            cb = g_new(struct qemu_plugin_cb, 1);
            cb->ctx = ctx;
            cb->f.generic = func;
            ctx->callbacks[ev] = cb;
            QLIST_INSERT_HEAD_RCU(&plugin.cb_lists[ev], cb, entry);
            if (!test_bit(ev, plugin.mask)) {
                set_bit(ev, plugin.mask);
                g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update__locked,
                                     NULL);
            }
        }
    } else {
        plugin_unregister_cb__locked(ctx, ev);
    }
 out_unlock:
    qemu_rec_mutex_unlock(&plugin.lock);
}

void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_INIT, cb);
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_EXIT, cb);
}

void qemu_plugin_register_vcpu_insn_cb(qemu_plugin_id_t id, qemu_plugin_vcpu_insn_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_INSN, cb);
}

void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{
    bool success;

    qemu_rec_mutex_lock(&plugin.lock);
    plugin_cpu_update__locked(&cpu->cpu_index, NULL, NULL);
    success = g_hash_table_insert(plugin.cpu_ht, &cpu->cpu_index,
                                  &cpu->cpu_index);
    g_assert(success);
    qemu_rec_mutex_unlock(&plugin.lock);

    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_INIT);
}

void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{
    bool success;

    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_EXIT);

    qemu_rec_mutex_lock(&plugin.lock);
    success = g_hash_table_remove(plugin.cpu_ht, &cpu->cpu_index);
    g_assert(success);
    qemu_rec_mutex_unlock(&plugin.lock);
}

struct plugin_for_each_args {
    struct qemu_plugin_ctx *ctx;
    qemu_plugin_vcpu_simple_cb_t cb;
};

static void plugin_vcpu_for_each(gpointer k, gpointer v, gpointer udata)
{
    struct plugin_for_each_args *args = udata;
    int cpu_index = *(int *)k;

    args->cb(args->ctx->id, cpu_index);
}

void qemu_plugin_vcpu_for_each(qemu_plugin_id_t id,
                               qemu_plugin_vcpu_simple_cb_t cb)
{
    struct plugin_for_each_args args;

    if (cb == NULL) {
        return;
    }
    qemu_rec_mutex_lock(&plugin.lock);
    args.ctx = id_to_ctx__locked(id);
    args.cb = cb;
    g_hash_table_foreach(plugin.cpu_ht, plugin_vcpu_for_each, &args);
    qemu_rec_mutex_unlock(&plugin.lock);
}

void helper_plugin_insn_cb(CPUArchState *env, void *ptr)
{
    CPUState *cpu = ENV_GET_CPU(env);
    struct qemu_plugin_insn *insn = ptr;
    struct qemu_plugin_cb *cb, *next;

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_VCPU_INSN], entry, next) {
        qemu_plugin_vcpu_insn_cb_t func = cb->f.vcpu_insn;

        func(cb->ctx->id, cpu->cpu_index, insn->data, insn->size);
    }
}

#if 0
static void plugin_tb_exec_cb(CPUState *cpu, struct qemu_plugin_cb *cb, const struct qemu_plugin_tb *tb)
{
    qemu_plugin_vcpu_tb_exec_cb_t func = cb->f.vcpu_tb_exec;
    struct qemu_plugin_tb_arg *arg;
    struct qemu_plugin_tb utb = {
        .insns = tb->insns,
        .n = tb->n,
        /* keep .arg_list away from plugin code */
    };

    /* pass the context's TB's userdata; NULL otherwise */
    QSLIST_FOREACH(arg, &tb->arg_list, entry) {
        if (arg->id == cb->ctx->id) {
            func(cb->ctx->id, cpu->cpu_index, &utb, arg->userp);
            return;
        }
    }
    func(cb->ctx->id, cpu->cpu_index, &utb, NULL);
}

void helper_plugin_tb_exec_cb(CPUArchState *env, void *ptr)
{
    CPUState *cpu = ENV_GET_CPU(env);
    const struct qemu_plugin_tb *tb = ptr;
    struct qemu_plugin_cb *cb, *next;

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_VCPU_TB_EXEC], entry, next) {

        plugin_tb_exec_cb(cpu, cb, tb);
    }
}
#endif

void qemu_plugin_tb_trans_cb(CPUState *cpu, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_cb *cb, *next;

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_VCPU_TB_TRANS], entry, next) {
        qemu_plugin_vcpu_tb_trans_cb_t func = cb->f.vcpu_tb_trans;
        void *userp = NULL;

        userp = func(cb->ctx->id, cpu->cpu_index, tb);
        if (userp != NULL) {
            struct qemu_plugin_tb_arg *a = g_new(struct qemu_plugin_tb_arg, 1);

            a->userp = userp;
            a->id = cb->ctx->id;
            /*
             * No need for a lock; the TB is not visible to other cpus yet, and
             * the list is only modified when the TB is deleted
             */
            QSLIST_INSERT_HEAD(&tb->arg_list, a, entry);
        }
    }
}

void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_TB_TRANS, cb);
}

#if 0
void qemu_plugin_register_vcpu_tb_exec_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_tb_exec_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_TB_EXEC, cb);
}
#endif

void qemu_plugin_register_vcpu_mem_exec_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_mem_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_MEM, cb);
}

void helper_plugin_mem_exec_cb(CPUArchState *env, target_ulong addr,
                               uint32_t info)
{
    struct qemu_plugin_cb *cb, *next;
    CPUState *cpu = ENV_GET_CPU(env);
    uint64_t vaddr = addr;
    uint8_t size_shift = info & MO_SIZE;
    bool store = !!((info >> 4) & 1);
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_MEM;

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_mem_cb_t func = cb->f.vcpu_mem;

        func(cb->ctx->id, cpu->cpu_index, vaddr, size_shift, store);
    }
}

void qemu_plugin_vcpu_mem_exec_cb(CPUState *cpu, uint64_t vaddr,
                                  uint8_t size_shift, bool store)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_MEM;

    if (!test_bit(ev, cpu->plugin_mask)) {
        return;
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_mem_cb_t func = cb->f.vcpu_mem;

        func(cb->ctx->id, cpu->cpu_index, vaddr, size_shift, store);
    }
}

void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_SYSCALL;

    if (!test_bit(ev, cpu->plugin_mask)) {
        return;
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_syscall_cb_t func = cb->f.vcpu_syscall;

        func(cb->ctx->id, cpu->cpu_index, num, a1, a2, a3, a4, a5, a6, a7, a8);
    }
}

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL, cb);
}

void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_SYSCALL_RET;

    if (!test_bit(ev, cpu->plugin_mask)) {
        return;
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_syscall_ret_cb_t func = cb->f.vcpu_syscall_ret;

        func(cb->ctx->id, cpu->cpu_index, num, ret);
    }
}

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL_RET, cb);
}

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
    return tb->n;
}

const struct qemu_plugin_insn *qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx)
{
    if (unlikely(idx >= tb->n)) {
        return NULL;
    }
    return tb->insns[idx];
}

const void *qemu_plugin_insn_data(const struct qemu_plugin_insn *insn)
{
    return insn->data;
}

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn)
{
    return insn->size;
}

void qemu_plugin_tb_remove(struct qemu_plugin_tb *tb)
{
    if (tb == NULL) {
        return;
    }
    for (;;) {
        struct qemu_plugin_tb_arg *arg = QSLIST_FIRST(&tb->arg_list);

        if (arg == NULL) {
            break;
        }
        QSLIST_REMOVE_HEAD(&tb->arg_list, entry);
        g_free(arg);
    }
    g_free(tb->insns);
    g_free(tb);
}

void qemu_plugin_vcpu_idle_cb(CPUState *cpu)
{
    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_IDLE);
}

void qemu_plugin_vcpu_resume_cb(CPUState *cpu)
{
    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_RESUME);
}

void qemu_plugin_register_vcpu_idle_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_IDLE, cb);
}

void qemu_plugin_register_vcpu_resume_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_RESUME, cb);
}

void qemu_plugin_register_flush_cb(qemu_plugin_id_t id,
                                   qemu_plugin_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_FLUSH, cb);
}

void qemu_plugin_flush_cb(void)
{
    plugin_cb__simple(QEMU_PLUGIN_EV_FLUSH);
}

int qemu_plugin_n_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return smp_cpus;
#endif
}

int qemu_plugin_n_max_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return max_cpus;
#endif
}

static void __attribute__((__constructor__)) plugin_init(void)
{
    int i;

    for (i = 0; i < QEMU_PLUGIN_EV_MAX; i++) {
        QLIST_INIT(&plugin.cb_lists[i]);
    }
    qemu_mutex_init(&plugin.lock);
    plugin.id_ht = g_hash_table_new(g_int64_hash, g_int64_equal);
    plugin.cpu_ht = g_hash_table_new(g_int_hash, g_int_equal);
    QTAILQ_INIT(&plugin.ctxs);
}
