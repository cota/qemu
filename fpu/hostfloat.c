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
 * We optimize the code further by deferring to soft-fp whenever FP
 * exception detection might get hairy. Fortunately this is not common.
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

#define GEN_INPUT_FLUSH(soft_t)                                         \
    static inline __attribute__((always_inline)) void                   \
    soft_t ## _input_flush__nocheck(soft_t *a, float_status *s)         \
    {                                                                   \
        if (unlikely(soft_t ## _is_denormal(*a))) {                     \
            *a = soft_t ## _set_sign(soft_t ## _zero,                   \
                                     soft_t ## _is_neg(*a));            \
            s->float_exception_flags |= float_flag_input_denormal;      \
        }                                                               \
    }                                                                   \
                                                                        \
    static inline __attribute__((always_inline)) void                   \
    soft_t ## _input_flush1(soft_t *a, float_status *s)                 \
    {                                                                   \
        if (likely(!s->flush_inputs_to_zero)) {                         \
            return;                                                     \
        }                                                               \
        soft_t ## _input_flush__nocheck(a, s);                          \
    }                                                                   \
                                                                        \
    static inline __attribute__((always_inline)) void                   \
    soft_t ## _input_flush2(soft_t *a, soft_t *b, float_status *s)      \
    {                                                                   \
        if (likely(!s->flush_inputs_to_zero)) {                         \
            return;                                                     \
        }                                                               \
        soft_t ## _input_flush__nocheck(a, s);                          \
        soft_t ## _input_flush__nocheck(b, s);                          \
    }                                                                   \
                                                                        \
    static inline __attribute__((always_inline)) void                   \
    soft_t ## _input_flush3(soft_t *a, soft_t *b, soft_t *c,            \
                            float_status *s)                            \
    {                                                                   \
        if (likely(!s->flush_inputs_to_zero)) {                         \
            return;                                                     \
        }                                                               \
        soft_t ## _input_flush__nocheck(a, s);                          \
        soft_t ## _input_flush__nocheck(b, s);                          \
        soft_t ## _input_flush__nocheck(c, s);                          \
    }

GEN_INPUT_FLUSH(float32)
GEN_INPUT_FLUSH(float64)
#undef GEN_INPUT_FLUSH

#define GEN_FPU_ADDSUB(add_name, sub_name, soft_t, host_t,              \
                       host_abs_func, min_normal)                       \
    static inline __attribute__((always_inline)) soft_t                 \
    fpu_ ## soft_t ## _addsub(soft_t a, soft_t b, bool subtract,        \
                              float_status *s)                          \
    {                                                                   \
        soft_t ## _input_flush2(&a, &b, s);                             \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   (soft_t ## _is_normal(b) || soft_t ## _is_zero(b)) && \
                   s->float_exception_flags & float_flag_inexact &&     \
                   s->float_rounding_mode == float_round_nearest_even)) { \
            host_t ha = soft_t ## _to_ ## host_t(a);                    \
            host_t hb = soft_t ## _to_ ## host_t(b);                    \
            host_t hr;                                                  \
            soft_t r;                                                   \
                                                                        \
            if (subtract) {                                             \
                hb = -hb;                                               \
            }                                                           \
            hr = ha + hb;                                               \
            r = host_t ## _to_ ## soft_t(hr);                           \
            if (unlikely(soft_t ## _is_infinity(r))) {                  \
                s->float_exception_flags |= float_flag_overflow;        \
            } else if (unlikely(host_abs_func(hr) <= min_normal) &&     \
                       !(soft_t ## _is_zero(a) &&                       \
                         soft_t ## _is_zero(b))) {                      \
                goto soft;                                              \
            }                                                           \
            return r;                                                   \
        }                                                               \
    soft:                                                               \
        if (subtract) {                                                 \
            return soft_ ## soft_t ## _sub(a, b, s);                    \
        } else {                                                        \
            return soft_ ## soft_t ## _add(a, b, s);                    \
        }                                                               \
    }                                                                   \
                                                                        \
    soft_t add_name(soft_t a, soft_t b, float_status *status)           \
    {                                                                   \
        return fpu_ ## soft_t ## _addsub(a, b, false, status);          \
    }                                                                   \
                                                                        \
    soft_t sub_name(soft_t a, soft_t b, float_status *status)           \
    {                                                                   \
        return fpu_ ## soft_t ## _addsub(a, b, true, status);           \
    }

GEN_FPU_ADDSUB(float32_add, float32_sub, float32, float, fabsf, FLT_MIN)
GEN_FPU_ADDSUB(float64_add, float64_sub, float64, double, fabs, DBL_MIN)
#undef GEN_FPU_ADDSUB

#define GEN_FPU_MUL(name, soft_t, host_t, host_abs_func, min_normal)    \
    soft_t name(soft_t a, soft_t b, float_status *s)                    \
    {                                                                   \
        soft_t ## _input_flush2(&a, &b, s);                             \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   (soft_t ## _is_normal(b) || soft_t ## _is_zero(b)) && \
                   s->float_exception_flags & float_flag_inexact &&     \
                   s->float_rounding_mode == float_round_nearest_even)) { \
            host_t ha = soft_t ## _to_ ## host_t(a);                    \
            host_t hb = soft_t ## _to_ ## host_t(b);                    \
            host_t hr = ha * hb;                                        \
            soft_t r = host_t ## _to_ ## soft_t(hr);                    \
                                                                        \
            if (unlikely(soft_t ## _is_infinity(r))) {                  \
                s->float_exception_flags |= float_flag_overflow;        \
            } else if (unlikely(host_abs_func(hr) <= min_normal) &&     \
                       !(soft_t ## _is_zero(a) ||                       \
                         soft_t ## _is_zero(b))) {                      \
                goto soft;                                              \
            }                                                           \
            return r;                                                   \
        }                                                               \
    soft:                                                               \
        return soft_ ## soft_t ## _mul(a, b, s);                        \
    }

GEN_FPU_MUL(float32_mul, float32, float, fabsf, FLT_MIN)
GEN_FPU_MUL(float64_mul, float64, double, fabs, DBL_MIN)
#undef GEN_FPU_MUL

#define GEN_FPU_DIV(name, soft_t, host_t, host_abs_func, min_normal)    \
    soft_t name(soft_t a, soft_t b, float_status *s)                    \
    {                                                                   \
        soft_t ## _input_flush2(&a, &b, s);                             \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   soft_t ## _is_normal(b) &&                           \
                   s->float_exception_flags & float_flag_inexact &&     \
                   s->float_rounding_mode == float_round_nearest_even)) { \
            host_t ha = soft_t ## _to_ ## host_t(a);                    \
            host_t hb = soft_t ## _to_ ## host_t(b);                    \
            host_t hr = ha / hb;                                        \
            soft_t r = host_t ## _to_ ## soft_t(hr);                    \
                                                                        \
            if (unlikely(soft_t ## _is_infinity(r))) {                  \
                s->float_exception_flags |= float_flag_overflow;        \
            } else if (unlikely(host_abs_func(hr) <= min_normal) &&     \
                       !soft_t ## _is_zero(a)) {                        \
                goto soft;                                              \
            }                                                           \
            return r;                                                   \
        }                                                               \
    soft:                                                               \
        return soft_ ## soft_t ## _div(a, b, s);                        \
    }

GEN_FPU_DIV(float32_div, float32, float, fabsf, FLT_MIN)
GEN_FPU_DIV(float64_div, float64, double, fabs, DBL_MIN)
#undef GEN_FPU_DIV

#define GEN_FPU_FMA(name, soft_t, host_t, host_fma_f, host_abs_f, min_normal) \
    soft_t name(soft_t a, soft_t b, soft_t c, int flags, float_status *s) \
    {                                                                   \
        soft_t ## _input_flush3(&a, &b, &c, s);                         \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   (soft_t ## _is_normal(b) || soft_t ## _is_zero(b)) && \
                   (soft_t ## _is_normal(c) || soft_t ## _is_zero(c)) && \
                   !(flags & float_muladd_halve_result) &&              \
                   s->float_exception_flags & float_flag_inexact &&     \
                   s->float_rounding_mode == float_round_nearest_even)) { \
            host_t ha, hb, hc, hr;                                      \
            soft_t r;                                                   \
            soft_t sa = flags & float_muladd_negate_product ?           \
                soft_t ## _chs(a) : a;                                  \
            soft_t sc = flags & float_muladd_negate_c ?                 \
                soft_t ## _chs(c) : c;                                  \
                                                                        \
            ha = soft_t ## _to_ ## host_t(sa);                          \
            hb = soft_t ## _to_ ## host_t(b);                           \
            hc = soft_t ## _to_ ## host_t(sc);                          \
            hr = host_fma_f(ha, hb, hc);                                \
            r = host_t ## _to_ ## soft_t(hr);                           \
                                                                        \
            if (unlikely(soft_t ## _is_infinity(r))) {                  \
                s->float_exception_flags |= float_flag_overflow;        \
            } else if (unlikely(host_abs_f(hr) <= min_normal) &&        \
                       !((soft_t ## _is_zero(a) ||                      \
                          soft_t ## _is_zero(b)) &&                     \
                         soft_t ## _is_zero(c))) {                      \
                goto soft;                                              \
            }                                                           \
            return flags & float_muladd_negate_result ?                 \
                soft_t ## _chs(r) : r;                                  \
        }                                                               \
    soft:                                                               \
        return soft_ ## soft_t ## _muladd(a, b, c, flags, s);           \
    }

GEN_FPU_FMA(float32_muladd, float32, float, fmaf, fabsf, FLT_MIN)
GEN_FPU_FMA(float64_muladd, float64, double, fma, fabs, DBL_MIN)
#undef GEN_FPU_FMA

#define GEN_FPU_SQRT(name, soft_t, host_t, host_sqrt_func)              \
    soft_t name(soft_t a, float_status *s)                              \
    {                                                                   \
        soft_t ## _input_flush1(&a, s);                                 \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   !soft_t ## _is_neg(a) &&                             \
                   s->float_exception_flags & float_flag_inexact &&     \
                   s->float_rounding_mode == float_round_nearest_even)) { \
            host_t ha = soft_t ## _to_ ## host_t(a);                    \
            host_t hr = host_sqrt_func(ha);                             \
                                                                        \
            return host_t ## _to_ ## soft_t(hr);                        \
        }                                                               \
        return soft_ ## soft_t ## _sqrt(a, s);                          \
    }

GEN_FPU_SQRT(float32_sqrt, float32, float, sqrtf)
GEN_FPU_SQRT(float64_sqrt, float64, double, sqrt)
#undef GEN_FPU_SQRT

#define GEN_FPU_COMPARE(name, soft_t, host_t)                           \
    static inline __attribute__((always_inline)) int                    \
    fpu_ ## name(soft_t a, soft_t b, bool is_quiet, float_status *s)    \
    {                                                                   \
        soft_t ## _input_flush2(&a, &b, s);                             \
        if (unlikely(soft_t ## _is_any_nan(a) ||                        \
                     soft_t ## _is_any_nan(b))) {                       \
            return soft_ ## name(a, b, is_quiet, s);                    \
        } else {                                                        \
            host_t ha = soft_t ## _to_ ## host_t(a);                    \
            host_t hb = soft_t ## _to_ ## host_t(b);                    \
                                                                        \
            if (isgreater(ha, hb)) {                                    \
                return float_relation_greater;                          \
            }                                                           \
            if (isless(ha, hb)) {                                       \
                return float_relation_less;                             \
            }                                                           \
            return float_relation_equal;                                \
        }                                                               \
    }                                                                   \
                                                                        \
    int name(soft_t a, soft_t b, float_status *s)                       \
    {                                                                   \
        return fpu_ ## name(a, b, false, s);                            \
    }                                                                   \
                                                                        \
    int name ## _quiet(soft_t a, soft_t b, float_status *s)             \
    {                                                                   \
        return fpu_ ## name(a, b, true, s);                             \
    }

GEN_FPU_COMPARE(float32_compare, float32, float)
GEN_FPU_COMPARE(float64_compare, float64, double)
#undef GEN_FPU_COMPARE

float64 float32_to_float64(float32 a, float_status *status)
{
    if (likely(float32_is_normal(a))) {
        float f = *(float *)&a;
        double r = f;

        return *(float64 *)&r;
    } else if (float32_is_zero(a)) {
        return float64_set_sign(float64_zero, float32_is_neg(a));
    } else {
        return soft_float32_to_float64(a, status);
    }
}
