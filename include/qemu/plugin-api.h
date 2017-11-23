/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_PLUGIN_API_H
#define QEMU_PLUGIN_API_H

#include <inttypes.h>
#include <stdbool.h>

/*
 * For best performance, build the plugin with -fvisibility=hidden so that
 * QEMU_PLUGIN_LOCAL is implicit. Then, just mark qemu_plugin_install with
 * QEMU_PLUGIN_EXPORT. For more info, see
 *   https://gcc.gnu.org/wiki/Visibility
 */
#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #define QEMU_PLUGIN_EXPORT __declspec(dllexport)
  #else
    #define QEMU_PLUGIN_EXPORT __declspec(dllimport)
  #endif
  #define QEMU_PLUGIN_LOCAL
#else
  #if __GNUC__ >= 4
    #define QEMU_PLUGIN_EXPORT __attribute__((visibility("default")))
    #define QEMU_PLUGIN_LOCAL  __attribute__((visibility("hidden")))
  #else
    #define QEMU_PLUGIN_EXPORT
    #define QEMU_PLUGIN_LOCAL
  #endif
#endif

typedef uint64_t qemu_plugin_id_t;

/**
 * qemu_plugin_install - Install a plugin
 * @id: this plugin's opaque ID
 * @argc: number of arguments
 * @argv: array of arguments (@argc elements)
 *
 * All plugins must export this symbol.
 *
 * Note: @argv is freed after this function returns.
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, int argc,
                                           char **argv);

typedef void (*qemu_plugin_uninstall_cb_t)(qemu_plugin_id_t id);

/**
 * qemu_plugin_uninstall - Uninstall a plugin
 * @id: this plugin's opaque ID
 * @cb: callback to be called once the plugin has been removed
 *
 * Do NOT assume that the plugin has been uninstalled once this
 * function returns. Plugins are uninstalled asynchronously,
 * and therefore the given plugin might still receive callbacks
 * from prior subscriptions _until_ @cb is called.
 */
void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_uninstall_cb_t cb);

typedef void (*qemu_plugin_simple_cb_t)(qemu_plugin_id_t id);

typedef void (*qemu_plugin_vcpu_simple_cb_t)(qemu_plugin_id_t id,
                                             unsigned int vcpu_index);

/**
 * qemu_plugin_register_vcpu_init_cb - register a vCPU initialization callback
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called every time a vCPU is initialized.
 *
 * See also: qemu_plugin_register_vcpu_exit_cb()
 */
void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);

/**
 * qemu_plugin_register_vcpu_exit_cb - register a vCPU exit callback
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called every time a vCPU exits.
 *
 * See also: qemu_plugin_register_vcpu_init_cb()
 */
void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);

void qemu_plugin_register_vcpu_idle_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb);

void qemu_plugin_register_vcpu_resume_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_simple_cb_t cb);

typedef void (*qemu_plugin_vcpu_insn_cb_t)(qemu_plugin_id_t id,
                                           unsigned int vcpu_index,
                                           const void *insn, size_t size);

void qemu_plugin_register_vcpu_insn_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_insn_cb_t cb);

struct qemu_plugin_tb;
struct qemu_plugin_insn;

typedef void *(*qemu_plugin_vcpu_tb_trans_cb_t)(qemu_plugin_id_t id,
                                                unsigned int vcpu_index,
                                                const struct qemu_plugin_tb *tb);

void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb);

typedef void (*qemu_plugin_vcpu_tb_exec_cb_t)(qemu_plugin_id_t id,
                                              unsigned int vcpu_index,
                                              const struct qemu_plugin_tb *tb,
                                              void *udata);

void qemu_plugin_register_vcpu_tb_exec_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_tb_exec_cb_t cb);

typedef void
(*qemu_plugin_vcpu_mem_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                             uint64_t vaddr, uint8_t size_shift,
                             bool store);

void qemu_plugin_register_vcpu_mem_exec_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_mem_cb_t cb);

typedef void
(*qemu_plugin_vcpu_syscall_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                                 int64_t num, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5,
                                 uint64_t a6, uint64_t a7, uint64_t a8);

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb);

typedef void
(*qemu_plugin_vcpu_syscall_ret_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_idx,
                                     int64_t num, int64_t ret);

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb);

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb);

const struct qemu_plugin_insn *qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx);

const void *qemu_plugin_insn_data(const struct qemu_plugin_insn *insn);

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn);

/**
 * qemu_plugin_vcpu_for_each - iterate over the existing vCPU
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called once for each existing vCPU.
 *
 * See also: qemu_plugin_register_vcpu_init_cb()
 */
void qemu_plugin_vcpu_for_each(qemu_plugin_id_t id,
                               qemu_plugin_vcpu_simple_cb_t cb);

void qemu_plugin_register_flush_cb(qemu_plugin_id_t id,
                                   qemu_plugin_simple_cb_t cb);

/* returns -1 in user-mode */
int qemu_plugin_n_vcpus(void);

/* returns -1 in user-mode */
int qemu_plugin_n_max_vcpus(void);

typedef void (*qemu_plugin_insn_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index, uint8_t *insn, size_t size);

#endif /* QEMU_PLUGIN_API_H */
