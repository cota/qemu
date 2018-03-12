#ifndef HW_POISON_H
#error Must define HW_POISON_H to work around TARGET_* poisoning
#endif

#include "qemu/osdep.h"
/* specialize the softfloat implementation based on TARGET_* */
#include "softfloat.c"

#include <fenv.h>
#include <math.h>

#include "qemu/bitops.h"

enum error {
    ERROR_NONE,
    ERROR_NOT_HANDLED,
    ERROR_INPUT,
    ERROR_RESULT,
    ERROR_EXCEPTIONS,
};

enum input_fmt {
    INPUT_FMT_IBM,
};

struct input {
    const char * const name;
    enum error (*test_line)(const char *line);
};

enum precision {
    PREC_FLOAT,
    PREC_DOUBLE,
    PREC_QUAD,
};

struct op_desc {
    const char * const name;
    int n_operands;
};

enum op {
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_SQRT,
};

static const struct op_desc ops[] = {
    [OP_ADD] =      { "+", 2 },
    [OP_SUB] =      { "-", 2 },
    [OP_MUL] =      { "*", 2 },
    [OP_DIV] =      { "/", 2 },
    [OP_SQRT] =     { "V", 1 },
};

struct test_op {
    uint64_t operands[3];
    uint64_t expected_result;
    enum precision prec;
    enum op op;
    signed char round;
    uint8_t trapped_exceptions;
    uint8_t exceptions;
    bool expected_result_is_valid;
    bool expected_nan;
};

typedef enum error (*tester_func_t)(const struct test_op *);

struct tester {
    tester_func_t func;
    const char *name;
};

static uint64_t test_stats[2];

static inline float u64_to_float(uint64_t v)
{
    uint32_t v32 = v;
    uint32_t *v32p = &v32;

    return *(float *)v32p;
}

static inline double u64_to_double(uint64_t v)
{
    uint64_t *vp = &v;

    return *(double *)vp;
}

static inline uint64_t float_to_u64(float f)
{
    float *fp = &f;

    return *(uint32_t *)fp;
}

static inline uint64_t double_to_u64(double d)
{
    double *dp = &d;

    return *(uint64_t *)dp;
}

static inline bool is_err(enum error err)
{
    return err != ERROR_NONE && err != ERROR_NOT_HANDLED;
}

static int host_exceptions_translate(int host_flags)
{
    int flags = 0;

    if (host_flags & FE_INEXACT) {
        flags |= float_flag_inexact;
    }
    if (host_flags & FE_UNDERFLOW) {
        flags |= float_flag_underflow;
    }
    if (host_flags & FE_OVERFLOW) {
        flags |= float_flag_overflow;
    }
    if (host_flags & FE_DIVBYZERO) {
        flags |= float_flag_divbyzero;
    }
    if (host_flags & FE_INVALID) {
        flags |= float_flag_invalid;
    }
    return flags;
}

static inline uint8_t host_get_exceptions(void)
{
    return host_exceptions_translate(fetestexcept(FE_ALL_EXCEPT));
}

static enum error tester_check(const struct test_op *t, uint64_t res64,
                               bool res_is_nan, uint8_t flags)
{
    enum error err = ERROR_NONE;

    if (t->expected_result_is_valid) {
        if (t->expected_nan) {
            if (!res_is_nan) {
                err = ERROR_RESULT;
                goto out;
            }
        } else if (res64 != t->expected_result) {
            err = ERROR_RESULT;
            goto out;
        }
    }
    if (t->exceptions && flags != t->exceptions) {
        if (t->exceptions == (float_flag_inexact | float_flag_underflow) &&
            flags == float_flag_inexact) {
            /*
             * this is probably OK -- some ppc hosts set the underflow
             * bit and others don't.
             */
        } else {
            err = ERROR_EXCEPTIONS;
            goto out;
        }
    }

 out:
    if (is_err(err)) {
        fprintf(stderr, "%s 0x%" PRIx64 " 0x%" PRIx64 ", expected: 0x%"
                PRIx64 ", returned: 0x%" PRIx64,
                ops[t->op].name, t->operands[0], t->operands[1],
                t->expected_result, res64);
        if (err == ERROR_EXCEPTIONS) {
            fprintf(stderr, ", expected exceptions: 0x%x, returned: 0x%x",
                    t->exceptions, flags);
        }
        fprintf(stderr, "\n");
    }
    return err;
}

static enum error host_tester(const struct test_op *t)
{
    uint64_t res64;
    bool result_is_nan;
    uint8_t flags = 0;

    if (t->exceptions) {
        feclearexcept(FE_ALL_EXCEPT);
    }

    if (t->prec == PREC_FLOAT) {
        float a = u64_to_float(t->operands[0]);
        float b = u64_to_float(t->operands[1]);
        float res;

        switch (t->op) {
        case OP_ADD:
            res = a + b;
            break;
        case OP_SUB:
            res = a - b;
            break;
        case OP_MUL:
            res = a * b;
            break;
        case OP_DIV:
            res = a / b;
            break;
        case OP_SQRT:
            res = sqrt(a);
            break;
        default:
            g_assert_not_reached();
        }
        if (t->exceptions) {
            flags = host_get_exceptions();
        }
        res64 = float_to_u64(res);
        result_is_nan = isnan(res);
    } else {
        return ERROR_NOT_HANDLED; /* XXX */
    }
    return tester_check(t, res64, result_is_nan, flags);
}

static enum error soft_tester(const struct test_op *t)
{
    uint64_t res64;
    static struct float_status status;
    enum error err = ERROR_NONE;
    bool result_is_nan;

    status.float_rounding_mode = t->round;
    status.float_exception_flags = 0;

    if (t->prec == PREC_FLOAT) {
        float32 a = t->operands[0];
        float32 b = t->operands[1];
        float32 res;

        switch (t->op) {
        case OP_ADD:
            res = float32_add(a, b, &status);
            break;
        case OP_SUB:
            res = float32_sub(a, b, &status);
            break;
        case OP_MUL:
            res = float32_mul(a, b, &status);
            break;
        case OP_DIV:
            res = float32_div(a, b, &status);
            break;
        case OP_SQRT:
            res = float32_sqrt(a, &status);
            break;
        default:
            return ERROR_NOT_HANDLED; /* XXX */
        }
        res64 = res;
        result_is_nan = isnan(*(float *)&res);
    } else {
        return ERROR_NOT_HANDLED; /* XXX */
    }
    return tester_check(t, res64, result_is_nan, status.float_exception_flags);
    return err;
}

static const struct tester valid_testers[] = {
    [0] = {
        .name = "host",
        .func = host_tester,
    },
    [1] = {
        .name = "soft",
        .func = soft_tester,
    },
};
static const struct tester *tester = &valid_testers[0];

static int ibm_get_exceptions(const char *p, uint8_t *excp)
{
    while (*p) {
        switch (*p) {
        case 'x':
            *excp |= float_flag_inexact;
            break;
        case 'u':
            *excp |= float_flag_underflow;
            break;
        case 'o':
            *excp |= float_flag_overflow;
            break;
        case 'z':
            *excp |= float_flag_divbyzero;
            break;
        case 'i':
            *excp |= float_flag_invalid;
            break;
        default:
            return 1;
        }
        p++;
    }
    return 0;
}

static uint64_t fp_choose(enum precision prec, uint64_t f, uint64_t d)
{
    switch (prec) {
    case PREC_FLOAT:
        return f;
    case PREC_DOUBLE:
        return d;
    default:
        g_assert_not_reached();
    }
}

static int
ibm_fp_hex(const char *p, enum precision prec, uint64_t *ret, bool *is_nan)
{
    int len;

    /* QNaN */
    if (unlikely(!strcmp("Q", p))) {
        *ret = fp_choose(prec, 0xffc00000, 0xfff8000000000000);
        if (is_nan) {
            *is_nan = true;
        }
        return 0;
    }
    /* SNaN */
    if (unlikely(!strcmp("S", p))) {
        *ret = fp_choose(prec, 0xffb00000, 0xfff7000000000000);
        if (is_nan) {
            *is_nan = true;
        }
        return 0;
    }
    if (unlikely(!strcmp("+Zero", p))) {
        *ret = fp_choose(prec, 0x00000000, 0x0000000000000000);
        return 0;
    }
    if (unlikely(!strcmp("-Zero", p))) {
        *ret = fp_choose(prec, 0x80000000, 0x8000000000000000);
        return 0;
    }
    if (unlikely(!strcmp("+inf", p) || !strcmp("+Inf", p))) {
        *ret = fp_choose(prec, 0x7f800000, 0x7ff0000000000000);
        return 0;
    }
    if (unlikely(!strcmp("-inf", p) || !strcmp("-Inf", p))) {
        *ret = fp_choose(prec, 0xff800000, 0xfff0000000000000);
        return 0;
    }

    len = strlen(p);

    if (strchr(p, 'P')) {
        bool negative = p[0] == '-';
        char *pos;
        bool denormal;

        if (len <= 4) {
            return 1;
        }
        denormal = p[1] == '0';
        if (prec == PREC_FLOAT) {
            uint32_t exponent;
            uint32_t significand;
            uint32_t h;

            significand = strtoul(&p[3], &pos, 16);
            if (*pos != 'P') {
                return 1;
            }
            pos++;
            exponent = strtol(pos, &pos, 10) + 127;
            if (pos != p + len) {
                return 1;
            }
            /*
             * When there's a leading zero, we have a denormal number. We'd
             * expect the input (unbiased) exponent to be -127, but for some
             * reason -126 is used. Correct that here.
             */
            if (denormal) {
                if (exponent != 1) {
                    return 1;
                }
                exponent = 0;
            }
            h = negative ? BIT(31) : 0;
            h |= exponent << 23;
            h |= significand;
            *ret = h;
            return 0;
        }
        if (prec == PREC_DOUBLE) {
            return 0; /* XXX */
        }
        g_assert_not_reached();
    } else if (strchr(p, 'E') || strchr(p, 'e')) {
        char *pos;

        if (prec == PREC_FLOAT) {
            float f = strtof(p, &pos);

            if (*pos) {
                return 1;
            }
            *ret = float_to_u64(f);
        }
        if (prec == PREC_DOUBLE) {
            return 0; /* XXX */
        }
        g_assert_not_reached();
    }
    return 1;
}

/* Syntax of IBM FP test cases:
 * https://www.research.ibm.com/haifa/projects/verification/fpgen/syntax.txt
 */
static enum error ibm_test_line(const char *line)
{
    struct test_op t;
    /* at most nine fields; this should be more than enough for each field */
    char s[9][64];
    char *p;
    int n, field;
    int i;

    /* data lines start with either b32 or d(64|128) */
    if (unlikely(line[0] != 'b' && line[0] != 'd')) {
        return ERROR_NOT_HANDLED;
    }
    n = sscanf(line, "%63s %63s %63s %63s %63s %63s %63s %63s %63s",
               s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8]);
    if (unlikely(n < 5 || n > 9)) {
        return ERROR_INPUT;
    }

    field = 0;
    p = s[field];
    if (unlikely(strlen(p) < 4)) {
        return ERROR_INPUT;
    }
    if (strncmp("b32", p, 3) == 0) {
        t.prec = PREC_FLOAT;
    } else if (strncmp("d64", p, 3) == 0) {
        t.prec = PREC_DOUBLE;
    } else if (strncmp("d128", p, 3) == 0) {
        return ERROR_NOT_HANDLED; /* XXX */
    } else {
        return ERROR_INPUT;
    }

    for (i = 0; i < ARRAY_SIZE(ops); i++) {
        if (strcmp(ops[i].name, &p[3]) == 0) {
            t.op = i;
            break;
        }
    }
    if (i == ARRAY_SIZE(ops)) {
        return ERROR_NOT_HANDLED;
    }

    field = 1;
    p = s[field];
    if (!strncmp("=0", p, 2)) {
        t.round = float_round_nearest_even;
    } else {
        return ERROR_NOT_HANDLED; /* XXX */
    }

    /* The trapped exceptions field is optional */
    t.trapped_exceptions = 0;
    field = 2;
    p = s[field];
    if (ibm_get_exceptions(p, &t.trapped_exceptions)) {
        if (unlikely(n == 9)) {
            return ERROR_INPUT;
        }
    } else {
        field++;
    }

    for (i = 0; i < ops[t.op].n_operands; i++) {
        p = s[field++];
        if (ibm_fp_hex(p, t.prec, &t.operands[i], NULL)) {
            return ERROR_INPUT;
        }
    }

    p = s[field++];
    if (strcmp("->", p)) {
        return ERROR_INPUT;
    }

    p = s[field++];
    if (unlikely(strcmp("#", p) == 0)) {
        t.expected_result_is_valid = false;
    } else {
        t.expected_nan = false;
        if (ibm_fp_hex(p, t.prec, &t.expected_result, &t.expected_nan)) {
            return ERROR_INPUT;
        }
        t.expected_result_is_valid = true;
    }

    /* the expected exceptions field is optional */
    t.exceptions = 0;
    if (field == n - 1) {
        p = s[field++];
        if (ibm_get_exceptions(p, &t.exceptions)) {
            return ERROR_INPUT;
        }
    }

    /*
     * We ignore "trapped exceptions" because we're not testing the trapping
     * mechanism of the host CPU.
     * We test though that the exception bits are correctly set.
     */
    if (t.trapped_exceptions) {
        return ERROR_NOT_HANDLED;
    }
    return tester->func(&t);
}

static const struct input valid_input_types[] = {
    [INPUT_FMT_IBM] = {
        .name = "ibm",
        .test_line = ibm_test_line,
    },
};

static const struct input *input_type = &valid_input_types[INPUT_FMT_IBM];

static void test_file(const char *filename)
{
    static char line[256];
    unsigned int i;
    FILE *fp;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "cannot open file '%s': %s\n",
                filename, strerror(errno));
        exit(EXIT_FAILURE);
    }
    i = 0;
    while (fgets(line, sizeof(line), fp)) {
        enum error err;

        i++;
        err = input_type->test_line(line);
        if (unlikely(is_err(err))) {
            switch (err) {
            case ERROR_INPUT:
                fprintf(stderr, "error: malformed input @ %s:%d:\n%s",
                        filename, i, line);
                break;
            case ERROR_RESULT:
                fprintf(stderr, "error: result mismatch for input @ %s:%d:\n%s",
                        filename, i, line);
                break;
            case ERROR_EXCEPTIONS:
                fprintf(stderr, "error: flags mismatch for input @ %s:%d:\n%s",
                        filename, i, line);
                break;
            default:
                g_assert_not_reached();
            }
            exit(EXIT_FAILURE);
        } else {
            test_stats[err]++;
        }
    }
    if (fclose(fp)) {
        fprintf(stderr, "warning: cannot close file '%s': %s\n",
                filename, strerror(errno));
    }
}

static void set_input_fmt(const char *optarg)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(valid_input_types); i++) {
        const struct input *type = &valid_input_types[i];

        if (strcmp(optarg, type->name) == 0) {
            input_type = type;
            return;
        }
    }
    fprintf(stderr, "Unknown input format '%s'", optarg);
    exit(EXIT_FAILURE);
}

static void set_tester(const char *optarg)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(valid_testers); i++) {
        const struct tester *t = &valid_testers[i];

        if (strcmp(optarg, t->name) == 0) {
            tester = t;
            return;
        }
    }
    fprintf(stderr, "Unknown tester '%s'", optarg);
    exit(EXIT_FAILURE);
}

static void usage_complete(int argc, char *argv[])
{
    fprintf(stderr, "Usage: %s [options] file1 [file2 ...]\n", argv[0]);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -f = format of the input file(s). Default: %s\n",
            valid_input_types[0].name);
    fprintf(stderr, "  -t = tester. Default: %s\n", valid_testers[0].name);
}

static void parse_opts(int argc, char *argv[])
{
    int c;

    for (;;) {
        c = getopt(argc, argv, "f:ht:");
        if (c < 0) {
            return;
        }
        switch (c) {
        case 'f':
            set_input_fmt(optarg);
            break;
        case 'h':
            usage_complete(argc, argv);
            exit(EXIT_SUCCESS);
        case 't':
            set_tester(optarg);
            break;
        }
    }
    g_assert_not_reached();
}

int main(int argc, char *argv[])
{
    int i;

    if (argc == 1) {
        usage_complete(argc, argv);
        exit(EXIT_FAILURE);
    }
    parse_opts(argc, argv);
    for (i = optind; i < argc; i++) {
        test_file(argv[i]);
    }
    printf("All tests OK. Passed: %"PRIu64", not handled: %"PRIu64"\n",
           test_stats[ERROR_NONE], test_stats[ERROR_NOT_HANDLED]);
    return 0;
}
