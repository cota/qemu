/*
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"

#include <math.h>

#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

enum op {
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
};

static const char * const op_names[] = {
    [OP_ADD] = "add",
    [OP_SUB] = "sub",
    [OP_MUL] = "mul",
    [OP_DIV] = "div",
};

static uint64_t n_ops = 1000000;
static enum op op;
static const char *precision = "float";

static const char commands_string[] =
    " -n = number of floating point operations\n"
    " -o = floating point operation (add, sub, mul, div). Default: add\n"
    " -p = precision (float, double). Default: float";

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

static inline float get_random_float(uint64_t *x)
{
    float f;

    do {
        *x = xorshift64star(*x);
        uint32_t r32 = *x;

        f = *(float *)&r32;
    } while (!isnormal(f));
    return f;
}

static inline float get_random_double(uint64_t *x)
{
    double d;

    do {
        *x = xorshift64star(*x);
        uint64_t r = *x;

        d = *(double *)&r;
    } while (!isnormal(d));
    return d;
}

#define GEN_BENCH_2OP(NAME, OP, PRECISION)                      \
    static PRECISION NAME(void)                                 \
    {                                                           \
        uint64_t ra = 0xdeadface;                               \
        uint64_t rb = 2001 + ra;                                \
        uint64_t i;                                             \
        PRECISION total = 0;                                    \
                                                                \
        for (i = 0; i < n_ops; i++) {                           \
            PRECISION a = glue(get_random_,PRECISION)(&ra);     \
            PRECISION b = glue(get_random_,PRECISION)(&rb);     \
                                                                \
            total += a OP b;                                    \
        }                                                       \
        return total;                                           \
    }

GEN_BENCH_2OP(bench_float_add, +, float)
GEN_BENCH_2OP(bench_float_sub, -, float)
GEN_BENCH_2OP(bench_float_mul, *, float)
GEN_BENCH_2OP(bench_float_div, /, float)

GEN_BENCH_2OP(bench_double_add, +, double)
GEN_BENCH_2OP(bench_double_sub, -, double)
GEN_BENCH_2OP(bench_double_mul, *, double)
GEN_BENCH_2OP(bench_double_div, /, double)

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
            break;
        case 'o':
            set_op(optarg);
            break;
        case 'p':
            precision = optarg;
            if (strcmp(precision, "float") && strcmp(precision, "double")) {
                fprintf(stderr, "Unsupported precision '%s'\n", precision);
                exit(EXIT_FAILURE);
            }
            break;
        }
    }
}

#define CALL_BENCH(OP, PRECISION, TOTAL)                        \
    do {                                                        \
        switch (OP) {                                           \
        case OP_ADD:                                            \
            TOTAL = glue(glue(bench_,PRECISION),_add)();        \
            break;                                              \
        case OP_SUB:                                            \
            TOTAL = glue(glue(bench_,PRECISION),_sub)();        \
            break;                                              \
        case OP_MUL:                                            \
            TOTAL = glue(glue(bench_,PRECISION),_mul)();        \
            break;                                              \
        case OP_DIV:                                            \
            TOTAL = glue(glue(bench_,PRECISION),_div)();        \
            break;                                              \
        default:                                                \
            g_assert_not_reached();                             \
        }                                                       \
    } while (0)

int main(int argc, char *argv[])
{
    int64_t t0, t1;
    double total;

    parse_args(argc, argv);
    if (!strcmp(precision, "float")) {
        t0 = get_clock_realtime();
        CALL_BENCH(op, float, total);
        t1 = get_clock_realtime();
    } else if (!strcmp(precision, "double")) {
        t0 = get_clock_realtime();
        CALL_BENCH(op, double, total);
        t1 = get_clock_realtime();
    } else {
        g_assert_not_reached();
    }
    printf("%.2f MFlops\n", (double)n_ops / (t1 - t0) * 1e3);
    /* use the variable total so that bench() doesn't get compiled away */
    if (total) {
        get_clock_realtime();
    }
    return 0;
}
