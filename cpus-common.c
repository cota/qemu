/*
 * CPU thread main loop - common bits for user and system mode emulation
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "exec/cpu-common.h"
#include "qom/cpu.h"
#include "sysemu/cpus.h"

static QemuMutex qemu_cpu_list_lock;
static QemuCond exclusive_resume;
static bool exclusive_ongoing;

void qemu_init_cpu_list(void)
{
    /* This is needed because qemu_init_cpu_list is also called by the
     * child process in a fork.  */
    exclusive_ongoing = false;

    qemu_mutex_init(&qemu_cpu_list_lock);
    qemu_cond_init(&exclusive_resume);
}

void cpu_list_lock(void)
{
    qemu_mutex_lock(&qemu_cpu_list_lock);
}

void cpu_list_unlock(void)
{
    qemu_mutex_unlock(&qemu_cpu_list_lock);
}

static bool cpu_index_auto_assigned;

static int cpu_get_free_index(void)
{
    CPUState *some_cpu;
    int cpu_index = 0;

    cpu_index_auto_assigned = true;
    CPU_FOREACH(some_cpu) {
        cpu_index++;
    }
    return cpu_index;
}

static void finish_safe_work(CPUState *cpu)
{
    cpu_exec_start(cpu);
    cpu_exec_end(cpu);
}

/* Wait for pending exclusive operations to complete.  The CPU list lock
   must be held.  */
static inline void exclusive_idle(void)
{
    while (exclusive_ongoing) {
        qemu_cond_wait(&exclusive_resume, &qemu_cpu_list_lock);
    }
}

void cpu_list_add(CPUState *cpu)
{
    CPUState *cs, *cs_next;

    qemu_mutex_lock(&qemu_cpu_list_lock);
    if (cpu->cpu_index == UNASSIGNED_CPU_INDEX) {
        cpu->cpu_index = cpu_get_free_index();
        assert(cpu->cpu_index != UNASSIGNED_CPU_INDEX);
    } else {
        assert(!cpu_index_auto_assigned);
    }

    /* make sure no exclusive jobs are running before touching the list */
    exclusive_idle();

    /* poor man's tail insert */
    CPU_FOREACH_SAFE(cs, cs_next) {
        if (cs_next == NULL) {
            break;
        }
    }
    if (cs == NULL) {
        QLIST_INSERT_HEAD_RCU(&cpus, cpu, node);
    } else {
        g_assert(cs_next == NULL);
        QLIST_INSERT_AFTER_RCU(cs, cpu, node);
    }
    cpu->in_cpu_list = true;

    qemu_mutex_unlock(&qemu_cpu_list_lock);

    finish_safe_work(cpu);
}

void cpu_list_remove(CPUState *cpu)
{
    qemu_mutex_lock(&qemu_cpu_list_lock);
    if (!cpu->in_cpu_list) {
        /* there is nothing to undo since cpu_exec_init() hasn't been called */
        qemu_mutex_unlock(&qemu_cpu_list_lock);
        return;
    }

    /* make sure no exclusive jobs are running before touching the list */
    exclusive_idle();

    QLIST_REMOVE_RCU(cpu, node);
    cpu->cpu_index = UNASSIGNED_CPU_INDEX;

    qemu_mutex_unlock(&qemu_cpu_list_lock);
}

struct qemu_work_item {
    QSIMPLEQ_ENTRY(qemu_work_item) node;
    run_on_cpu_func func;
    run_on_cpu_data data;
    bool free, exclusive, done;
};

static void queue_work_on_cpu__locked(CPUState *cpu, struct qemu_work_item *wi)
{
    QSIMPLEQ_INSERT_TAIL(&cpu->queued_work, wi, node);
    wi->done = false;

    qemu_cpu_kick(cpu);
}

static void queue_work_on_cpu(CPUState *cpu, struct qemu_work_item *wi)
{
    qemu_mutex_lock(&cpu->lock);
    queue_work_on_cpu__locked(cpu, wi);
    qemu_mutex_unlock(&cpu->lock);
}

void do_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data)
{
    struct qemu_work_item wi;
    bool has_bql = qemu_mutex_iothread_locked();

    if (qemu_cpu_is_self(cpu)) {
        func(cpu, data);
        return;
    }

    if (has_bql) {
        qemu_mutex_unlock_iothread();
    }

    wi.func = func;
    wi.data = data;
    wi.done = false;
    wi.free = false;
    wi.exclusive = false;

    qemu_mutex_lock(&cpu->lock);
    queue_work_on_cpu__locked(cpu, &wi);

    while (!atomic_mb_read(&wi.done)) {
        CPUState *self_cpu = current_cpu;

        qemu_cond_wait(&cpu->work_cond, &cpu->lock);
        current_cpu = self_cpu;
    }
    qemu_mutex_unlock(&cpu->lock);

    if (has_bql) {
        qemu_mutex_lock_iothread();
    }
}

void async_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data)
{
    struct qemu_work_item *wi;

    wi = g_malloc0(sizeof(struct qemu_work_item));
    wi->func = func;
    wi->data = data;
    wi->free = true;

    queue_work_on_cpu(cpu, wi);
}

/* Start an exclusive operation.
   Must only be called from outside cpu_exec.  */
void start_exclusive(void)
{
    CPUState *other_cpu;

    /* prevent CPU list modifications until we are done */
    qemu_mutex_lock(&qemu_cpu_list_lock);
    exclusive_idle();
    exclusive_ongoing = true;
    qemu_mutex_unlock(&qemu_cpu_list_lock);

    /* kick running CPUs */
    CPU_FOREACH(other_cpu) {
        qemu_mutex_lock(&other_cpu->lock);
        if (other_cpu->running) {
            other_cpu->exclusive_req_waiter = true;
            qemu_cpu_kick(other_cpu);
        }
        other_cpu->exclusive_req = true;
        qemu_mutex_unlock(&other_cpu->lock);
    }

    /* wait for CPUs that were running to clear us */
    CPU_FOREACH(other_cpu) {
        qemu_mutex_lock(&other_cpu->lock);
        while (other_cpu->exclusive_req_waiter) {
            qemu_cond_wait(&other_cpu->exclusive_req_cond, &other_cpu->lock);
        }
        qemu_mutex_unlock(&other_cpu->lock);

    }
}

/* Finish an exclusive operation.  */
void end_exclusive(void)
{
    CPUState *other_cpu;

    CPU_FOREACH(other_cpu) {
        qemu_mutex_lock(&other_cpu->lock);
        g_assert(!other_cpu->exclusive_req_waiter);
        other_cpu->exclusive_req = false;
        qemu_cond_signal(&other_cpu->exclusive_req_cond);
        qemu_mutex_unlock(&other_cpu->lock);
    }

    qemu_mutex_lock(&qemu_cpu_list_lock);
    exclusive_ongoing = false;
    qemu_cond_broadcast(&exclusive_resume);
    qemu_mutex_unlock(&qemu_cpu_list_lock);
}

static void cpu_exclusive_pending__locked(CPUState *cpu)
{
    g_assert(!cpu->running);

    if (cpu->exclusive_req_waiter) {
        cpu->exclusive_req_waiter = false;
        qemu_cond_signal(&cpu->exclusive_req_cond);
    }
    while (cpu->exclusive_req) {
        qemu_cond_wait(&cpu->exclusive_req_cond, &cpu->lock);
    }
}

/* call with cpu->lock held */
void cpu_exec_start__locked(CPUState *cpu)
{
    cpu_exclusive_pending__locked(cpu);
    cpu->running = true;
    qemu_mutex_unlock(&cpu->lock);
}

/* Wait for exclusive ops to finish, and begin cpu execution.  */
void cpu_exec_start(CPUState *cpu)
{
    qemu_mutex_lock(&cpu->lock);
    cpu_exec_start__locked(cpu);
}

/* returns with cpu->lock held */
void cpu_exec_end__retlocked(CPUState *cpu)
{
    qemu_mutex_lock(&cpu->lock);
    cpu->running = false;
    cpu_exclusive_pending__locked(cpu);
}

/* Mark cpu as not executing, and wait for exclusive ops to finish */
void cpu_exec_end(CPUState *cpu)
{
    cpu_exec_end__retlocked(cpu);
    qemu_mutex_unlock(&cpu->lock);
}

void async_safe_run_on_cpu(CPUState *cpu, run_on_cpu_func func,
                           run_on_cpu_data data)
{
    struct qemu_work_item *wi;

    wi = g_malloc0(sizeof(struct qemu_work_item));
    wi->func = func;
    wi->data = data;
    wi->free = true;
    wi->exclusive = true;

    queue_work_on_cpu(cpu, wi);
}

void process_queued_cpu_work(CPUState *cpu)
{
    struct qemu_work_item *wi;
    bool has_bql = qemu_mutex_iothread_locked();

    qemu_mutex_lock(&cpu->lock);
    while (!QSIMPLEQ_EMPTY(&cpu->queued_work)) {
        wi = QSIMPLEQ_FIRST(&cpu->queued_work);
        QSIMPLEQ_REMOVE_HEAD(&cpu->queued_work, node);
        qemu_mutex_unlock(&cpu->lock);
        if (wi->exclusive) {
            /* Running work items outside the BQL avoids the following deadlock:
             * 1) start_exclusive() is called with the BQL taken while another
             * CPU is running; 2) cpu_exec in the other CPU tries to takes the
             * BQL, so it goes to sleep; start_exclusive() is sleeping too, so
             * neither CPU can proceed.
             */
            if (has_bql) {
                qemu_mutex_unlock_iothread();
            }
            start_exclusive();
            wi->func(cpu, wi->data);
            end_exclusive();
            if (has_bql) {
                qemu_mutex_lock_iothread();
            }
        } else {
            wi->func(cpu, wi->data);
        }
        qemu_mutex_lock(&cpu->lock);
        if (wi->free) {
            g_free(wi);
        } else {
            atomic_mb_set(&wi->done, true);
        }
    }
    qemu_mutex_unlock(&cpu->lock);
    qemu_cond_broadcast(&cpu->work_cond);
}
