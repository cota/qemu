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

struct qemu_plugin_cb {
    struct qemu_plugin_ctx *ctx;
    union {
        qemu_plugin_vcpu_simple_cb_t vcpu_simple_cb;
        void *func;
    };
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
    bool uninstalling; /* protected by plugin.lock */
};

/* global state */
struct qemu_plugin_state {
    QTAILQ_HEAD(, qemu_plugin_ctx) ctxs;
    struct qemu_plugin_cb_head cb_lists[QEMU_PLUGIN_EV_MAX];
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
     * The lock must be acquired by all API ops. Since some API ops
     * call plugin code repeatedly (e.g. vcpu_for_each), we keep
     * a counter to allow for recursive acquisitions.
     */
    QemuMutex lock;
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
static __thread bool plugin_lock_held;

static inline void plugin_lock(void)
{
    g_assert(!plugin_lock_held);
    qemu_mutex_lock(&plugin.lock);
    plugin_lock_held = true;
}

static inline void plugin_unlock(void)
{
    plugin_lock_held = false;
    qemu_mutex_unlock(&plugin.lock);
}

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

    plugin_lock();

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
    plugin_unlock();

    rc = install(ctx->id, desc->argc, desc->argv);
    if (rc) {
        error_report("%s: qemu_plugin_install returned error code %d",
                     __func__, rc);
        /*
         * we cannot rely on the plugin doing its own cleanup, so
         * call a full uninstall if the plugin did not already call it.
         */
        plugin_lock();
        if (!ctx->uninstalling) {
            qemu_plugin_uninstall(ctx->id);
        }
        plugin_unlock();
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

static struct qemu_plugin_ctx *id_to_ctx(qemu_plugin_id_t id)
{
    struct qemu_plugin_ctx *ctx;
    qemu_plugin_id_t *id_p;

    g_assert(plugin_lock_held);
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

static void plugin_cpu_update(gpointer k, gpointer v, gpointer udata)
{
    CPUState *cpu = container_of(k, CPUState, cpu_index);
    run_on_cpu_data mask = RUN_ON_CPU_HOST_ULONG(*plugin.mask);

    g_assert(plugin_lock_held);

    if (cpu->created) {
        async_run_on_cpu(cpu, plugin_cpu_update__async, mask);
    } else {
        plugin_cpu_update__async(cpu, mask);
    }
}

static void plugin_unregister_cb(struct qemu_plugin_ctx *ctx,
                                 enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb = ctx->callbacks[ev];

    g_assert(plugin_lock_held);

    if (cb == NULL) {
        return;
    }
    QLIST_REMOVE_RCU(cb, entry);
    g_free(cb);
    ctx->callbacks[ev] = NULL;
    if (QLIST_EMPTY_RCU(&plugin.cb_lists[ev])) {
        clear_bit(ev, plugin.mask);
        g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update, NULL);
    }
}

static void plugin_destroy__rcuthread(struct qemu_plugin_ctx *ctx)
{
    plugin_lock();
    QTAILQ_REMOVE(&plugin.ctxs, ctx, entry);
    g_assert(ctx->uninstalling);
    plugin_unlock();

    if (dlclose(ctx->handle)) {
        warn_report("%s: %s", __func__, dlerror());
    }
    qemu_vfree(ctx);
}

void qemu_plugin_uninstall(qemu_plugin_id_t id)
{
    struct qemu_plugin_ctx *ctx;
    enum qemu_plugin_event ev;
    bool success;

    plugin_lock();
    ctx = id_to_ctx(id);
    if (unlikely(ctx->uninstalling)) {
        error_report("plugin: called %s more than once", __func__);
        abort();
    }
    ctx->uninstalling = true;
    /*
     * Unregister all callbacks. This is an RCU list so it is possible that some
     * callbacks will still be called in this RCU grace period. For this reason
     * we cannot yet free the context nor invalidate its id.
     */
    for (ev = 0; ev < QEMU_PLUGIN_EV_MAX; ev++) {
        plugin_unregister_cb(ctx, ev);
    }
    success = g_hash_table_remove(plugin.id_ht, &ctx->id);
    g_assert(success);
    plugin_unlock();

    call_rcu(ctx, plugin_destroy__rcuthread, rcu);
}

static void plugin_vcpu_cb__simple(CPUState *cpu, enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_VCPU_INIT:
    case QEMU_PLUGIN_EV_VCPU_EXIT:
        /* iterate safely; plugins might uninstall themselves at any time */
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_vcpu_simple_cb_t func = cb->vcpu_simple_cb;

            func(cb->ctx->id, cpu->cpu_index);
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

    plugin_lock();
    ctx = id_to_ctx(id);
    if (func) {
        struct qemu_plugin_cb *cb = ctx->callbacks[ev];

        if (cb) {
            cb->func = func;
        } else {
            cb = g_new(struct qemu_plugin_cb, 1);
            cb->ctx = ctx;
            cb->func = func;
            ctx->callbacks[ev] = cb;
            QLIST_INSERT_HEAD_RCU(&plugin.cb_lists[ev], cb, entry);
            if (!test_bit(ev, plugin.mask)) {
                set_bit(ev, plugin.mask);
                g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update, NULL);
            }
        }
    } else {
        plugin_unregister_cb(ctx, ev);
    }
    plugin_unlock();
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

void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{
    bool success;

    plugin_lock();
    success = g_hash_table_insert(plugin.cpu_ht, &cpu->cpu_index,
                                  &cpu->cpu_index);
    g_assert(success);
    plugin_unlock();

    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_INIT);
}

void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{
    bool success;

    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_EXIT);

    plugin_lock();
    success = g_hash_table_remove(plugin.cpu_ht, &cpu->cpu_index);
    g_assert(success);
    plugin_unlock();
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
    plugin_lock();
    args.ctx = id_to_ctx(id);
    args.cb = cb;
    g_hash_table_foreach(plugin.cpu_ht, plugin_vcpu_for_each, &args);
    plugin_unlock();
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
