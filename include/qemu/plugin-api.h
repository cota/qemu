/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_PLUGIN_API_H
#define QEMU_PLUGIN_API_H

#include <inttypes.h>

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

/**
 * qemu_plugin_uninstall - Uninstall a plugin
 * @id: this plugin's opaque ID
 *
 * Removes all callbacks and unloads the plugin.
 *
 * Once this function returns, no further API calls from it are allowed.
 *
 * Note: if the plugin is multi-threaded (e.g. it is subscribed to callbacks
 * from vCPUs running in parallel), some time will elapse before changes
 * propagate to all threads, and therefore some callbacks might still be called
 * for a short period of time after this function returns.
 */
void qemu_plugin_uninstall(qemu_plugin_id_t id);

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

/**
 * qemu_plugin_vcpu_for_each - iterate over the existing vCPU
 * @id: plugin ID
 * @cb: callback function
 *
 * The @cb function is called once for each existing vCPU.
 * Note: to avoid deadlock, @cb cannot make any other qemu_plugin_*() call.
 *
 * See also: qemu_plugin_register_vcpu_init_cb()
 */
void qemu_plugin_vcpu_for_each(qemu_plugin_id_t id,
                               qemu_plugin_vcpu_simple_cb_t cb);

#endif /* QEMU_PLUGIN_API_H */
