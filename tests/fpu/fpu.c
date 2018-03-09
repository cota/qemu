#include "qemu/osdep.h"
#include <glib/gprintf.h>

#include "qemu/bitops.h"

enum error {
    ERROR_NONE,
    ERROR_INPUT,
    ERROR_FP,
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

enum op {
    OP_ADD,
    /* XXX */
    OP_MAX_NR,
};

static const char * const op_str[OP_MAX_NR] = {
    [OP_ADD] = "+",
};

struct test_op {
    uint64_t a;
    uint64_t b;
    uint64_t expected_result;
    enum precision prec;
    enum op op;
    signed char round;
    uint8_t trapped_exceptions;
    uint8_t expected_exceptions;
    bool expected_result_is_valid;
};

typedef enum error (*tester_func_t)(const struct test_op *);

struct tester {
    tester_func_t func;
    const char *name;
};

static enum error ibm_test_line(const char *line);

static const struct input valid_input_types[] = {
    [INPUT_FMT_IBM] = {
        .name = "ibm",
        .test_line = ibm_test_line,
    },
};

static enum error host_noflags_tester(const struct test_op *t);

static const struct tester valid_testers[] = {
    [0] = {
        .name = "host-noflags",
        .func = host_noflags_tester,
    },
};

static const struct input *input_type = &valid_input_types[INPUT_FMT_IBM];
static const struct tester *tester = &valid_testers[0];
//static struct float_status status;

static void usage_complete(int argc, char *argv[])
{
    fprintf(stderr, "Usage: %s [options] file1 [file2 ...]\n", argv[0]);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -f = format of the input file(s). Default: %s\n",
            valid_input_types[0].name);
    fprintf(stderr, "  -t = tester. Default: %s\n", valid_testers[0].name);
}

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
            *excp |= float_flag_invalid;;
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

static int ibm_fp_hex(const char *p, enum precision prec, uint64_t *ret)
{
    int len;
    bool negative;

    if (unlikely(p[0] == 'Q')) {
        *ret = fp_choose(prec, 0xffc00000, 0xfff8000000000000);
        return 0;
    }
    if (unlikely(p[0] == 'S')) {
        *ret = fp_choose(prec, 0xffb00000, 0xfff7000000000000);
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
    if (len <= 4) {
        return 1;
    }
    negative = !strncmp(p, "-1", 2);
    if (prec == PREC_FLOAT) {
        uint32_t exponent;
        uint32_t significand;
        uint32_t h;
        char *pos;

        significand = strtoul(&p[3], &pos, 16);
        if (*pos != 'P') {
            return 1;
        }
        pos++;
        exponent = strtol(pos, &pos, 10) + 127;
        if (pos != p + len) {
            return 1;
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

    /* data lines start with either b32 or d(64|128) */
    if (unlikely(line[0] != 'b' && line[0] != 'd')) {
        return ERROR_NONE;
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
        return ERROR_NONE; /* XXX */
    } else {
        return ERROR_INPUT;
    }

    if (strcmp("+", &p[3]) == 0) {
        t.op = OP_ADD;
    } else {
        return ERROR_NONE; /* XXX */
    }

    field = 1;
    p = s[field];
    if (!strncmp("=0", p, 2)) {
        t.round = float_round_nearest_even;
    } else {
        return ERROR_NONE; /* XXX */
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

    p = s[field++];
    if (ibm_fp_hex(p, t.prec, &t.a)) {
        return ERROR_INPUT;
    }
    p = s[field++];
    if (ibm_fp_hex(p, t.prec, &t.b)) {
        return ERROR_INPUT;
    }

    p = s[field++];
    if (strcmp("->", p)) {
        return ERROR_INPUT;
    }

    p = s[field++];
    if (unlikely(strcmp("#", p) == 0)) {
        t.expected_result_is_valid = false;
    } else {
        if (ibm_fp_hex(p, t.prec, &t.expected_result)) {
            return ERROR_INPUT;
        }
        t.expected_result_is_valid = true;
    }

    /* the expected exceptions field is optional */
    t.expected_exceptions = 0;
    if (field == n - 1) {
        p = s[field++];
        if (ibm_get_exceptions(p, &t.expected_exceptions)) {
            return ERROR_INPUT;
        }
    }

    return tester->func(&t);
}

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
        if (unlikely(err)) {
            switch (err) {
            case ERROR_INPUT:
                fprintf(stderr, "Malformed input at %s:%d:\n%s",
                        filename, i, line);
                break;
            case ERROR_FP:
                fprintf(stderr, "Computation error for input at %s:%d:\n%s",
                        filename, i, line);
                break;
            default:
                g_assert_not_reached();
            }
            exit(EXIT_FAILURE);
        }
    }
    if (fclose(fp)) {
        fprintf(stderr, "warning: cannot close file '%s': %s\n",
                filename, strerror(errno));
    }
}

static enum error host_noflags_tester(const struct test_op *t)
{
    uint64_t res64;

    if (t->prec == PREC_FLOAT) {
        float a = u64_to_float(t->a);
        float b = u64_to_float(t->b);
        float res;

        switch (t->op) {
        case OP_ADD:
            res = a + b;
            break;
        default:
            g_assert_not_reached();
        }
        res64 = float_to_u64(res);
    } else {
        return ERROR_NONE; /* XXX */
    }
    if (res64 != t->expected_result) {
        fprintf(stderr, "%s 0x%" PRIx64 " 0x%" PRIx64 ", expected: 0x%"
                PRIx64 ", obtained: 0x%" PRIx64 "\n",
                op_str[t->op], t->a, t->b, t->expected_result, res64);
        return ERROR_FP;
    }
    return ERROR_NONE;
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

static void parse_opts(int argc, char *argv[])
{
    int c;

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

int main(int argc, char *argv[])
{
    int i;

    if (argc == 1) {
        usage_complete(argc, argv);
        exit(EXIT_FAILURE);
    }
    parse_opts(argc, argv);
    for (i = 1; i < argc; i++) {
        test_file(argv[i]);
    }
    return 0;
}
