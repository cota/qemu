/*
 * hostfloat.c - FP primitives that use the host's FPU whenever possible.
 *
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * Fast emulation of guest FP instructions is challenging for two reasons.
 * First, FP instruction semantics are similar but not identical, particularly
 * when handling NaNs. Second, emulating at reasonable speed the guest FP
 * exception flags is not trivial: reading the host's flags register with a
 * feclearexcept & fetestexcept pair is slow [slightly slower than soft-fp],
 * and trapping on every FP exception is not fast nor pleasant to work with.
 *
 * This module leverages the host FPU for a subset of the operations. To
 * do this it follows the main idea presented in this paper:
 *
 * Guo, Yu-Chuan, et al. "Translating the ARM Neon and VFP instructions in a
 * binary translator." Software: Practice and Experience 46.12 (2016):1591-1615.
 *
 * The idea is thus to leverage the host FPU to (1) compute FP operations
 * and (2) identify whether FP exceptions occurred while avoiding
 * expensive exception flag register accesses.
 *
 * An important optimization shown in the paper is that given that exception
 * flags are rarely cleared by the guest, we can avoid recomputing some flags.
 * This is particularly useful for the inexact flag, which is very frequently
 * raised in floating-point workloads.
 *
 * For most operations we make additional assumptions that further increase
 * speed and simplify the code. These assumptions are:
 * - Inputs are normal or, where applicable, zero. Otherwise defer to soft-fp.
 * - Guest uses default rounding (to nearest). Otherwise defer to soft-fp.
 */
#include <math.h>

#include "qemu/osdep.h"
#include "fpu/softfloat.h"

#define GEN_TYPE_CONV(name, to_t, from_t)       \
    static inline to_t name(from_t a)           \
    {                                           \
        to_t r = *(to_t *)&a;                   \
        return r;                               \
    }

GEN_TYPE_CONV(float32_to_float, float, float32)
GEN_TYPE_CONV(float64_to_double, double, float64)
GEN_TYPE_CONV(float_to_float32, float32, float)
GEN_TYPE_CONV(double_to_float64, float64, double)
#undef GEN_TYPE_CONV
