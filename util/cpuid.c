#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/cpuid.h"

#include <cpuid.h>

static bool cpuid_feat[QEMU_CPUID_NR_FEATURES];
static bool cpuid_inited;

/* Leaf 1, %edx */
#ifndef bit_CMOV
#define bit_CMOV        (1 << 15)
#endif
#ifndef bit_SSE2
#define bit_SSE2        (1 << 26)
#endif

/* Leaf 1, %ecx */
#ifndef bit_SSE4_1
#define bit_SSE4_1      (1 << 19)
#endif
#ifndef bit_MOVBE
#define bit_MOVBE       (1 << 22)
#endif
#ifndef bit_OSXSAVE
#define bit_OSXSAVE     (1 << 27)
#endif
#ifndef bit_AVX
#define bit_AVX         (1 << 28)
#endif

/* Leaf 7, %ebx */
#ifndef bit_BMI
#define bit_BMI         (1 << 3)
#endif
#ifndef bit_AVX2
#define bit_AVX2        (1 << 5)
#endif
#ifndef bit_BMI2
#define bit_BMI2        (1 << 8)
#endif

/* Leaf 0x80000001, %ecx */
#ifndef bit_LZCNT
#define bit_LZCNT       (1 << 5)
#endif

static void qemu_cpuid_init(void)
{
    unsigned a, b, c, d, b7 = 0;
    int max = __get_cpuid_max(0, 0);

    if (max >= 7) {
        /* BMI1 is available on AMD Piledriver and Intel Haswell CPUs.  */
        __cpuid_count(7, 0, a, b7, c, d);
        cpuid_feat[QEMU_CPUID_BMI] = !!(b7 & bit_BMI);
        cpuid_feat[QEMU_CPUID_BMI2] = !!(b7 & bit_BMI2);
    }

    if (max >= 1) {
        __cpuid(1, a, b, c, d);

        cpuid_feat[QEMU_CPUID_CMOV] = !!(d & bit_CMOV);
        cpuid_feat[QEMU_CPUID_SSE2] = !!(d & bit_SSE2);

        cpuid_feat[QEMU_CPUID_SSE4] = !!(c & bit_SSE4_1);
        /* MOVBE is only available on Intel Atom and Haswell CPUs, so we
           need to probe for it.  */
        cpuid_feat[QEMU_CPUID_MOVBE] = !!(c & bit_MOVBE);
        cpuid_feat[QEMU_CPUID_POPCNT] = !!(c & bit_POPCNT);

        /* There are a number of things we must check before we can be
           sure of not hitting invalid opcode.  */
        if (c & bit_OSXSAVE) {
            unsigned xcrl, xcrh;
            /* The xgetbv instruction is not available to older versions of
             * the assembler, so we encode the instruction manually.
             */
            asm(".byte 0x0f, 0x01, 0xd0" : "=a" (xcrl), "=d" (xcrh) : "c" (0));
            if ((xcrl & 6) == 6) {
                cpuid_feat[QEMU_CPUID_AVX] = !!(c & bit_AVX);
                cpuid_feat[QEMU_CPUID_AVX2] = !!(b7 & bit_AVX2);
            }
        }
    }

    max = __get_cpuid_max(0x8000000, 0);
    if (max >= 1) {
        __cpuid(0x80000001, a, b, c, d);
        /* LZCNT was introduced with AMD Barcelona and Intel Haswell CPUs.  */
        cpuid_feat[QEMU_CPUID_LZCNT] = !!(c & bit_LZCNT);
    }
}

bool qemu_cpuid_supports(enum qemu_cpuid_feature feat)
{
    if (unlikely(!cpuid_inited)) {
        qemu_cpuid_init();
    }
    return cpuid_feat[feat];
}
