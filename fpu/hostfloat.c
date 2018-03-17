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

#define GEN_FPU_ADDSUB(add_name, sub_name, soft_t, host_t)              \
    static soft_t fpu_ ## soft_t ## _addsub(soft_t a, soft_t b,         \
                                            bool subtract,              \
                                            float_status *s)            \
    {                                                                   \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   (soft_t ## _is_normal(b) || soft_t ## _is_zero(b)) && \
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
            if (soft_t ## _is_infinity(r)) {                            \
                s->float_exception_flags |= float_flag_overflow;        \
            }                                                           \
            if (unlikely(!(s->float_exception_flags &                   \
                           float_flag_inexact)) &&                      \
                (hr - ha != hb || hr - hb != ha)) {                     \
                s->float_exception_flags |= float_flag_inexact;         \
            }                                                           \
            return r;                                                   \
        }                                                               \
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
    }                                                                   \

GEN_FPU_ADDSUB(float32_add, float32_sub, float32, float)
GEN_FPU_ADDSUB(float64_add, float64_sub, float64, double)
#undef GEN_FPU_ADDSUB

#define GEN_FPU_MUL(name, soft_t, host_t, host_abs_func, min_normal)    \
    soft_t name(soft_t a, soft_t b, float_status *s)                    \
    {                                                                   \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   (soft_t ## _is_normal(b) || soft_t ## _is_zero(b)) && \
                   s->float_exception_flags & float_flag_inexact &&     \
                   s->float_rounding_mode == float_round_nearest_even)) { \
            if (soft_t ## _is_zero(a) || soft_t ## _is_zero(b)) {       \
                bool signbit = soft_t ## _is_neg(a) ^ soft_t ## _is_neg(b); \
                                                                        \
                return soft_t ## _set_sign(0, signbit);                 \
            } else {                                                    \
                host_t ha = soft_t ## _to_ ## host_t(a);                \
                host_t hb = soft_t ## _to_ ## host_t(b);                \
                host_t hr = ha * hb;                                    \
                soft_t r = host_t ## _to_ ## soft_t(hr);                \
                                                                        \
                if (unlikely(soft_t ## _is_infinity(r))) {              \
                    s->float_exception_flags |= float_flag_overflow;    \
                } else if (unlikely(host_abs_func(hr) <= min_normal)) { \
                    goto soft;                                          \
                }                                                       \
                return r;                                               \
            }                                                           \
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
        if (likely(soft_t ## _is_normal(a) &&                           \
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
            } else if (unlikely(host_abs_func(hr) <= min_normal)) {     \
                goto soft;                                              \
            }                                                           \
            return r;                                                   \
        }                                                               \
     soft:                                                              \
        return soft_ ## soft_t ## _div(a, b, s);                        \
    }

GEN_FPU_DIV(float32_div, float32, float, fabsf, FLT_MIN)
GEN_FPU_DIV(float64_div, float64, double, fabs, DBL_MIN)
#undef GEN_FPU_DIV

/*
 * When (a || b) == 0, there's no need to check for overflow, since we
 * know the addend is normal || zero and the product is zero.
 */
#define GEN_FPU_FMA(name, soft_t, host_t, host_fma_f, host_abs_f, min_normal) \
    soft_t name(soft_t a, soft_t b, soft_t c, int flags, float_status *s) \
    {                                                                   \
        if (likely((soft_t ## _is_normal(a) || soft_t ## _is_zero(a)) && \
                   (soft_t ## _is_normal(b) || soft_t ## _is_zero(b)) && \
                   (soft_t ## _is_normal(c) || soft_t ## _is_zero(c)) && \
                   !(flags & float_muladd_halve_result) &&              \
                   s->float_exception_flags & float_flag_inexact &&     \
                   s->float_rounding_mode == float_round_nearest_even)) { \
            if (soft_t ## _is_zero(a) || soft_t ## _is_zero(b)) {       \
                soft_t p, r;                                            \
                host_t hp, hc, hr;                                      \
                bool prod_sign;                                         \
                                                                        \
                prod_sign = soft_t ## _is_neg(a) ^ soft_t ## _is_neg(b); \
                prod_sign ^= !!(flags & float_muladd_negate_product);   \
                p = soft_t ## _set_sign(0, prod_sign);                  \
                                                                        \
                if (flags & float_muladd_negate_c) {                    \
                    c = soft_t ## _chs(c);                              \
                }                                                       \
                                                                        \
                hp = soft_t ## _to_ ## host_t(p);                       \
                hc = soft_t ## _to_ ## host_t(c);                       \
                hr = hp + hc;                                           \
                r = host_t ## _to_ ## soft_t(hr);                       \
                return flags & float_muladd_negate_result ?             \
                    soft_t ## _chs(r) : r;                              \
            } else {                                                    \
                host_t ha, hb, hc, hr;                                  \
                soft_t r;                                               \
                soft_t sa = flags & float_muladd_negate_product ?       \
                    soft_t ## _chs(a) : a;                              \
                soft_t sc = flags & float_muladd_negate_c ?             \
                    soft_t ## _chs(c) : c;                              \
                                                                        \
                ha = soft_t ## _to_ ## host_t(sa);                      \
                hb = soft_t ## _to_ ## host_t(b);                       \
                hc = soft_t ## _to_ ## host_t(sc);                      \
                hr = host_fma_f(ha, hb, hc);                            \
                r = host_t ## _to_ ## soft_t(hr);                       \
                                                                        \
                if (unlikely(soft_t ## _is_infinity(r))) {              \
                    s->float_exception_flags |= float_flag_overflow;    \
                } else if (unlikely(host_abs_f(hr) <= min_normal)) {    \
                    goto soft;                                          \
                }                                                       \
                return flags & float_muladd_negate_result ?             \
                    soft_t ## _chs(r) : r;                              \
            }                                                           \
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
    static int fpu_ ## name(soft_t a, soft_t b, bool is_quiet,          \
                            float_status *s)                            \
    {                                                                   \
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
    int __attribute__((flatten)) name(soft_t a, soft_t b,               \
                                      float_status *s)                  \
    {                                                                   \
        return fpu_ ## name(a, b, false, s);                            \
    }                                                                   \
                                                                        \
    int __attribute__((flatten))                                        \
    name ## _quiet(soft_t a, soft_t b, float_status *s)                 \
    {                                                                   \
        return fpu_ ## name(a, b, true, s);                             \
    }

GEN_FPU_COMPARE(float32_compare, float32, float)
GEN_FPU_COMPARE(float64_compare, float64, double)
#undef GEN_FPU_COMPARE
