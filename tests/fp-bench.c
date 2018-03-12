/*
 * fp-bench.c - A collection of simple floating point microbenchmarks.
 *
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"

#include <math.h>

#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

/* amortize the computation of random inputs */
#define OPS_PER_ITER     (1000ULL)

#define SEED_A 0xdeadfacedeadface
#define SEED_B 0xbadc0feebadc0fee
#define SEED_C 0xbeefdeadbeefdead

enum op {
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_FMA,
    OP_SQRT,
};

static const char * const op_names[] = {
    [OP_ADD] = "add",
    [OP_SUB] = "sub",
    [OP_MUL] = "mul",
    [OP_DIV] = "div",
    [OP_FMA] = "fma",
    [OP_SQRT] = "sqrt",
};

static uint64_t n_ops = 10000000;
static enum op op;
static const char *precision = "float";

static const char commands_string[] =
    " -n = number of floating point operations\n"
    " -o = floating point operation (add, sub, mul, div, fma, sqrt). Default: add\n"
    " -p = precision (float|single, double). Default: float";

static void usage_complete(int argc, char *argv[])
{
    fprintf(stderr, "Usage: %s [options]\n", argv[0]);
    fprintf(stderr, "options:\n%s\n", commands_string);
    exit(-1);
}

static void set_op(const char *name)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(op_names); i++) {
        if (strcmp(name, op_names[i]) == 0) {
            op = i;
            return;
        }
    }
    fprintf(stderr, "Unsupported op '%s'\n", name);
    exit(EXIT_FAILURE);
}

static inline int64_t get_clock_realtime(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
}

/*
 * From: https://en.wikipedia.org/wiki/Xorshift
 * This is faster than rand_r(), and gives us a wider range (RAND_MAX is only
 * guaranteed to be >= INT_MAX).
 */
static uint64_t xorshift64star(uint64_t x)
{
    x ^= x >> 12; /* a */
    x ^= x << 25; /* b */
    x ^= x >> 27; /* c */
    return x * UINT64_C(2685821657736338717);
}

static inline bool u32_is_normal(uint32_t x)
{
    return ((x + 0x00800000) & 0x7fffffff) >= 0x01000000;
}

static inline bool u64_is_normal(uint64_t x)
{
    return ((x + (1ULL << 52)) & -1ULL >> 1) >= 1ULL << 53;
}

static inline float get_random_float(uint64_t *x)
{
    uint64_t r = *x;
    uint32_t r32;

    do {
        r = xorshift64star(r);
    } while (!u32_is_normal(r));
    *x = r;
    r32 = r;
    return *(float *)&r32;
}

static inline double get_random_double(uint64_t *x)
{
    uint64_t r = *x;

    do {
        r = xorshift64star(r);
    } while (!u64_is_normal(r));
    *x = r;
    return *(double *)&r;
}

/*
 * Disable optimizations (e.g. "a OP b" outside of the inner loop) with
 * volatile.
 */
#define GEN_BENCH_1OPF(NAME, FUNC, PRECISION)                           \
    static void NAME(volatile PRECISION *res)                           \
    {                                                                   \
        uint64_t ra = SEED_A;                                           \
        uint64_t i, j;                                                  \
                                                                        \
        for (i = 0; i < n_ops; i += OPS_PER_ITER) {                     \
            volatile PRECISION a = glue(get_random_, PRECISION)(&ra);   \
                                                                        \
            for (j = 0; j < OPS_PER_ITER; j++) {                        \
                *res = FUNC(a);                                         \
            }                                                           \
        }                                                               \
    }

GEN_BENCH_1OPF(bench_float_sqrt, sqrtf, float)
GEN_BENCH_1OPF(bench_double_sqrt, sqrt, double)
#undef GEN_BENCH_1OPF

#define GEN_BENCH_2OP(NAME, OP, PRECISION)                              \
    static void NAME(volatile PRECISION *res)                           \
    {                                                                   \
        uint64_t ra = SEED_A;                                           \
        uint64_t rb = SEED_B;                                           \
        uint64_t i, j;                                                  \
                                                                        \
        for (i = 0; i < n_ops; i += OPS_PER_ITER) {                     \
            volatile PRECISION a = glue(get_random_, PRECISION)(&ra);   \
            volatile PRECISION b = glue(get_random_, PRECISION)(&rb);   \
                                                                        \
            for (j = 0; j < OPS_PER_ITER; j++) {                        \
                *res = a OP b;                                          \
            }                                                           \
        }                                                               \
    }

GEN_BENCH_2OP(bench_float_add, +, float)
GEN_BENCH_2OP(bench_float_sub, -, float)
GEN_BENCH_2OP(bench_float_mul, *, float)
GEN_BENCH_2OP(bench_float_div, /, float)

GEN_BENCH_2OP(bench_double_add, +, double)
GEN_BENCH_2OP(bench_double_sub, -, double)
GEN_BENCH_2OP(bench_double_mul, *, double)
GEN_BENCH_2OP(bench_double_div, /, double)

#define GEN_BENCH_3OPF(NAME, FUNC, PRECISION)                           \
    static void NAME(volatile PRECISION *res)                           \
    {                                                                   \
        uint64_t ra = SEED_A;                                           \
        uint64_t rb = SEED_B;                                           \
        uint64_t rc = SEED_C;                                           \
        uint64_t i, j;                                                  \
                                                                        \
        for (i = 0; i < n_ops; i += OPS_PER_ITER) {                     \
            volatile PRECISION a = glue(get_random_, PRECISION)(&ra);   \
            volatile PRECISION b = glue(get_random_, PRECISION)(&rb);   \
            volatile PRECISION c = glue(get_random_, PRECISION)(&rc);   \
                                                                        \
            for (j = 0; j < OPS_PER_ITER; j++) {                        \
                *res = FUNC(a, b, c);                                   \
            }                                                           \
        }                                                               \
    }

GEN_BENCH_3OPF(bench_float_fma, fmaf, float)
GEN_BENCH_3OPF(bench_double_fma, fma, double)
#undef GEN_BENCH_3OPF

static void parse_args(int argc, char *argv[])
{
    int c;

    for (;;) {
        c = getopt(argc, argv, "n:ho:p:");
        if (c < 0) {
            break;
        }
        switch (c) {
        case 'h':
            usage_complete(argc, argv);
            exit(0);
        case 'n':
            n_ops = atoll(optarg);
            if (n_ops < OPS_PER_ITER) {
                n_ops = OPS_PER_ITER;
            }
            n_ops -= n_ops % OPS_PER_ITER;
            break;
        case 'o':
            set_op(optarg);
            break;
        case 'p':
            precision = optarg;
            if (strcmp(precision, "float") &&
                strcmp(precision, "single") &&
                strcmp(precision, "double")) {
                fprintf(stderr, "Unsupported precision '%s'\n", precision);
                exit(EXIT_FAILURE);
            }
            break;
        }
    }
}

#define CALL_BENCH(OP, PRECISION, RESP)                 \
    do {                                                \
        switch (OP) {                                   \
        case OP_ADD:                                    \
            glue(glue(bench_, PRECISION), _add)(RESP);  \
            break;                                      \
        case OP_SUB:                                    \
            glue(glue(bench_, PRECISION), _sub)(RESP);  \
            break;                                      \
        case OP_MUL:                                    \
            glue(glue(bench_, PRECISION), _mul)(RESP);  \
            break;                                      \
        case OP_DIV:                                    \
            glue(glue(bench_, PRECISION), _div)(RESP);  \
            break;                                      \
        case OP_FMA:                                    \
            glue(glue(bench_, PRECISION), _fma)(RESP);  \
            break;                                      \
        case OP_SQRT:                                   \
            glue(glue(bench_, PRECISION), _sqrt)(RESP); \
            break;                                      \
        default:                                        \
            g_assert_not_reached();                     \
        }                                               \
    } while (0)

int main(int argc, char *argv[])
{
    int64_t t0, t1;
    double resd;

    parse_args(argc, argv);
    if (!strcmp(precision, "float") || !strcmp(precision, "single")) {
        float res;
        t0 = get_clock_realtime();
        CALL_BENCH(op, float, &res);
        t1 = get_clock_realtime();
        resd = res;
    } else if (!strcmp(precision, "double")) {
        t0 = get_clock_realtime();
        CALL_BENCH(op, double, &resd);
        t1 = get_clock_realtime();
    } else {
        g_assert_not_reached();
    }
    printf("%.2f MFlops\n", (double)n_ops / (t1 - t0) * 1e3);
    if (resd) {
        return 0;
    }
    return 0;
}
