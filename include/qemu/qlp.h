/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_QLP_H
#define QEMU_QLP_H

#include "qemu/fprintf-fn.h"

#ifdef CONFIG_LOCK_PROFILER

struct QemuMutex;

void qlp_mutex_lock(struct QemuMutex *mutex, const char *file, unsigned line);
int qlp_mutex_trylock(struct QemuMutex *mutex, const char *file, unsigned line);
void qlp_report(FILE *f, fprintf_function cpu_fprintf);

#else /* !CONF_LOCK_PROFILER */

static inline void qlp_report(FILE *f, fprintf_function cpu_fprintf)
{
    cpu_fprintf(f, "[Lock profiler not compiled]\n");
}

#endif /* !CONF_LOCK_PROFILER */

#endif /* QEMU_QLP_H */
