/*
 * qlp.c - QEMU Lock Profiler
 *
 * Copyright (C) 2016, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qemu/qlp.h"
#include "exec/tb-hash-xx.h"

/*
 * Each thread keeps a hash table of the mutexes it has acquired.
 * When preparing a report, we iterate over the threads' hash tables,
 * aggregating results.
 */
struct qlp_thread {
    GHashTable *ht;
    QTAILQ_ENTRY(qlp_thread) entry;
    /* lock with do_qemu_mutex_lock to avoid recursion */
    QemuMutex lock;
};

struct qlp_callsite {
    QemuMutex *mutex;
    const char *file; /* i.e. __FILE__; shortened at report time */
    unsigned int line;
};

struct qlp_mutex {
    struct qlp_callsite callsite;
    uint64_t n_acqs;
    uint64_t n_failed_acqs;
    uint64_t ns;
    uint64_t max_ns;
    double avg_ns;
};

struct qlp_pr_args {
    fprintf_function pr;
    FILE *f;
    unsigned max_rows;
};

static __thread struct qlp_thread *qlp;
/* lock with do_qemu_mutex_lock */
static QemuMutex qlp_list_lock;
QTAILQ_HEAD(, qlp_thread) qlp_list = QTAILQ_HEAD_INITIALIZER(qlp_list);
static size_t qlp_qemu_path_len;

static guint qlp_mutex_ht_hash(gconstpointer key)
{
    const struct qlp_callsite *s = key;
    uint64_t a = (uint64_t)s->mutex;

    return tb_hash_func7(a, g_str_hash(s->file), s->line, 0, 0);
}

static gboolean qlp_mutex_ht_cmp(gconstpointer ap, gconstpointer bp)
{
    const struct qlp_callsite *a = ap;
    const struct qlp_callsite *b = bp;

    return a->mutex == b->mutex &&
        a->line == b->line &&
        !strcmp(a->file, b->file);
}

static void qlp_init(void)
{
    qlp = g_new0(struct qlp_thread, 1);
    qlp->ht = g_hash_table_new(qlp_mutex_ht_hash, qlp_mutex_ht_cmp);
    qemu_mutex_init(&qlp->lock);

    do_qemu_mutex_lock(&qlp_list_lock);
    if (qlp_qemu_path_len == 0) {
        qlp_qemu_path_len = strlen(__FILE__) - strlen("util/qlp.c");
    }
    QTAILQ_INSERT_TAIL(&qlp_list, qlp, entry);
    qemu_mutex_unlock(&qlp_list_lock);
}

/* free string with g_free */
static char *qlp_at(const struct qlp_callsite *callsite)
{
    GString *s = g_string_new("");
    const char *shortened;

    /* remove the absolute path to qemu */
    if (unlikely(strlen(callsite->file) < qlp_qemu_path_len)) {
        shortened = callsite->file;
    } else {
        shortened = callsite->file + qlp_qemu_path_len;
    }
    g_string_append_printf(s, "%s:%u", shortened, callsite->line);
    return g_string_free(s, FALSE);
}

static struct qlp_mutex *qlp_mutex_create(GHashTable *ht,
                                          struct qlp_callsite *callsite)
{
    struct qlp_mutex *m;
    bool success;

    m = g_new0(struct qlp_mutex, 1);
    memcpy(&m->callsite, callsite, sizeof(*callsite));
    success = g_hash_table_insert(ht, &m->callsite, m);
    g_assert(success);

    return m;
}

/* call with qlp->lock held */
static struct qlp_mutex *qlp_mutex_find(GHashTable *ht,
                                        struct qlp_callsite *site)
{
    struct qlp_mutex *m;

    m = g_hash_table_lookup(ht, site);
    if (m == NULL) {
        m = qlp_mutex_create(ht, site);
    }
    return m;
}

static int do_qlp_mutex_lock(QemuMutex *mutex, const char *file, unsigned line,
                             bool try)
{
    struct qlp_mutex *m;
    struct qlp_callsite callsite = {
        .mutex = mutex,
        .file = file,
        .line = line,
    };
    uint64_t ns;
    int64_t t;
    int err = 0;

    if (qlp == NULL) {
        qlp_init();
    }
    do_qemu_mutex_lock(&qlp->lock);
    m = qlp_mutex_find(qlp->ht, &callsite);
    qemu_mutex_unlock(&qlp->lock);

    t = get_clock();
    if (try) {
        err = do_qemu_mutex_trylock(mutex);
    } else {
        do_qemu_mutex_lock(mutex);
    }
    ns = get_clock() - t;
    if (ns > m->max_ns) {
        atomic_set(&m->max_ns, ns);
    }
    atomic_set(&m->ns, m->ns + ns);
    atomic_set(&m->n_acqs, m->n_acqs + 1);
    if (try && err) {
        atomic_set(&m->n_failed_acqs, m->n_failed_acqs + 1);
    }
    return err;
}

void qlp_mutex_lock(struct QemuMutex *mutex, const char *file, unsigned line)
{
    do_qlp_mutex_lock(mutex, file, line, false);
}

int qlp_mutex_trylock(struct QemuMutex *mutex, const char *file, unsigned line)
{
    return do_qlp_mutex_lock(mutex, file, line, true);
}

static gint qlp_tree_cmp(gconstpointer ap, gconstpointer bp, gpointer up)
{
    const struct qlp_mutex *a = ap;
    const struct qlp_mutex *b = bp;

    if (a->avg_ns > b->avg_ns) {
        return -1;
    } else if (a->avg_ns < b->avg_ns) {
        return 1;
    } else {
        const struct qlp_callsite *ca = &a->callsite;
        const struct qlp_callsite *cb = &b->callsite;

        /* same avg_ns. Break the tie with the mutex' address */
        if (ca->mutex < cb->mutex) {
            return -1;
        } else if (ca->mutex > cb->mutex) {
            return 1;
        } else {
            int cmp;

            /* same mutex. Break the tie with the callsite's file */
            cmp = strcmp(ca->file, cb->file);
            if (cmp) {
                return cmp;
            }
            /* same callsite file. Break the tie with the callsite's line */
            g_assert(ca->line != cb->line);
            if (ca->line < cb->line) {
                return -1;
            }
            return 1;
        }
    }
}

/* iterate over a qlp_thread. Iterate with the qlp's lock held */
static void qlp_aggregate(gpointer key, gpointer value, gpointer udata)
{
    struct qlp_mutex *th_m = value;
    struct qlp_mutex *m;
    struct qlp_callsite *callsite = key;
    GHashTable *ht = udata;

    m = qlp_mutex_find(ht, callsite);
    m->ns += th_m->ns;
    m->n_acqs += th_m->n_acqs;
    if (th_m->max_ns > m->max_ns) {
        m->max_ns = th_m->max_ns;
    }
}

static void qlp_sort(gpointer key, gpointer value, gpointer udata)
{
    struct qlp_mutex *m = value;
    GTree *tree = udata;

    m->avg_ns = m->n_acqs ? (double)m->ns / m->n_acqs : 0;

    g_tree_insert(tree, m, NULL);
}

/* @tree is the tree of mutex calls, sorted by avg_ns contended time */
static void qlp_mktree(GTree *tree)
{
    struct qlp_thread *qlp;
    GHashTable *ht;

    /* first, create a hash table to aggregate all results */
    ht = g_hash_table_new(qlp_mutex_ht_hash, qlp_mutex_ht_cmp);

    do_qemu_mutex_lock(&qlp_list_lock);
    /*
     * Then fill in the hash table by iterating over each thread.
     * We could first acquire all locks, but don't bother.
     */
    QTAILQ_FOREACH(qlp, &qlp_list, entry) {
        do_qemu_mutex_lock(&qlp->lock);
        g_hash_table_foreach(qlp->ht, qlp_aggregate, ht);
        qemu_mutex_unlock(&qlp->lock);
    }
    qemu_mutex_unlock(&qlp_list_lock);

    /* sort the hash table elements by using a tree */
    g_hash_table_foreach(ht, qlp_sort, tree);

    /* free the hash table, but keep the elements (those are in the tree now) */
    g_hash_table_destroy(ht);
}

static gboolean qlp_tree_report(gpointer key, gpointer value, gpointer udata)
{
    struct qlp_mutex *m = key;
    struct qlp_pr_args *args = udata;
    char *callsite;

    if (args->max_rows-- == 0) {
        return TRUE;
    }

    callsite = qlp_at(&m->callsite);
    args->pr(args->f,
             "%18p   %12" PRIu64 "      %10" PRIu64 "   %13.3f   %13.3f   %s\n",
             m->callsite.mutex, m->n_acqs, m->n_failed_acqs, m->avg_ns / 1000,
             (double)m->max_ns / 1000.0, callsite);
    g_free(callsite);

    return FALSE;
}

void qlp_report(FILE *f, fprintf_function cpu_fprintf)
{
    GTree *tree = g_tree_new_full(qlp_tree_cmp, NULL, g_free, NULL);
    struct qlp_pr_args args = {
        .f = f,
        .pr = cpu_fprintf,
        .max_rows = 10,
    };

    qlp_mktree(tree);
    if (g_tree_nnodes(tree) > 0) {
        cpu_fprintf(f,
                    "        Lock vaddr         # Acqs   # Failed Acqs   "
                    "Avg Wait (us)   Max Wait (us)   Call site\n");
        g_tree_foreach(tree, qlp_tree_report, &args);
    } else {
        cpu_fprintf(f, "No locks acquired yet.\n");
    }
    g_tree_destroy(tree);
}

static void __attribute__((constructor)) init_qlp(void)
{
    qemu_mutex_init(&qlp_list_lock);
}
