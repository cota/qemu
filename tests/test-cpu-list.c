/*
 * CPU list test.
 *
 * Copyright (C) 2020 Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"

#include "qemu-common.h"
#include "cpus-common-shim.h"

static void test2(void)
{
    CPUState cpus[2];
    int i;

    cpus_common_shim_init();

    for (i = 0; i < ARRAY_SIZE(cpus); i++) {
        cpus[i].cpu_index = UNASSIGNED_CPU_INDEX;
    }

    cpu_list_add(&cpus[0]);
    g_assert_cmpint(cpus[0].cpu_index, ==, 0);
    cpu_list_add(&cpus[1]);
    g_assert_cmpint(cpus[1].cpu_index, ==, 1);

    cpu_list_remove(&cpus[0]);
    g_assert_cmpint(cpus[0].cpu_index, ==, UNASSIGNED_CPU_INDEX);
    cpu_list_add(&cpus[0]);
    g_assert_cmpint(cpus[0].cpu_index, ==, 0);

    /* remove all CPUs at the end of this test because the bitmap is global */
    for (i = 0; i < ARRAY_SIZE(cpus); i++) {
        cpu_list_remove(&cpus[i]);
    }
}

static void test3(void)
{
    CPUState cpus[3];
    int i;

    cpus_common_shim_init();

    for (i = 0; i < ARRAY_SIZE(cpus); i++) {
        cpus[i].cpu_index = UNASSIGNED_CPU_INDEX;
    }

    cpu_list_add(&cpus[0]);
    cpu_list_add(&cpus[1]);
    cpu_list_add(&cpus[2]);
    g_assert_cmpint(cpus[2].cpu_index, ==, 2);

    /* remove and re-add the middle CPU */
    cpu_list_remove(&cpus[1]);
    g_assert_cmpint(cpus[1].cpu_index, ==, UNASSIGNED_CPU_INDEX);
    cpu_list_add(&cpus[1]);
    g_assert_cmpint(cpus[1].cpu_index, ==, 1);

    /* remove and re-add the first and last CPUs */
    cpu_list_remove(&cpus[2]);
    cpu_list_remove(&cpus[0]);
    cpu_list_add(&cpus[2]);
    g_assert_cmpint(cpus[2].cpu_index, ==, 0);
    cpu_list_add(&cpus[0]);
    g_assert_cmpint(cpus[0].cpu_index, ==, 2);

    /* remove all CPUs at the end of this test because the bitmap is global */
    for (i = 0; i < ARRAY_SIZE(cpus); i++) {
        cpu_list_remove(&cpus[i]);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/cpu-list/2cpus", test2);
    g_test_add_func("/cpu-list/3cpus", test3);
    return g_test_run();
}
