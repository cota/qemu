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
    QEMU_PLUGIN_EV_MAX,
};

#ifdef CONFIG_PLUGINS

void qemu_plugin_vcpu_init_hook(CPUState *cpu);
void qemu_plugin_vcpu_exit_hook(CPUState *cpu);

#else /* !CONFIG_PLUGINS */

static inline void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{ }

#endif /* !CONFIG_PLUGINS */

#endif /* QEMU_PLUGIN_H */
