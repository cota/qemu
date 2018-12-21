/* cpuid.h: Macros to identify the properties of an x86 host.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_CPUID_H
#define QEMU_CPUID_H

/* Cover the uses that we have within qemu */
enum qemu_cpuid_feature {
    QEMU_CPUID_BMI,
    QEMU_CPUID_BMI2,
    QEMU_CPUID_CMOV,
    QEMU_CPUID_MOVBE,
    QEMU_CPUID_POPCNT,
    QEMU_CPUID_AVX,
    QEMU_CPUID_AVX2,
    QEMU_CPUID_LZCNT,
    QEMU_CPUID_SSE2,
    QEMU_CPUID_SSE4,
    QEMU_CPUID_FMA3,
    QEMU_CPUID_FMA4,
    QEMU_CPUID_NR_FEATURES,
};

#ifdef CONFIG_CPUID_H
bool qemu_cpuid_supports(enum qemu_cpuid_feature feat);
#else
static inline bool qemu_cpuid_supports(enum qemu_cpuid_feature feat)
{
    return false;
}
#endif /* CONFIG_CPUID_H */

#endif /* QEMU_CPUID_H */
