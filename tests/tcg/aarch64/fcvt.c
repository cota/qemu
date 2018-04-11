/*
 * Test Floating Point Conversion
 */

#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <float.h>
#include <fenv.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static char flag_str[256];

static char * get_flag_state(int flags)
{
    if (flags) {
        snprintf(flag_str, sizeof(flag_str), "%s %s %s %s %s",
                 flags & FE_OVERFLOW ? "OVERFLOW" : "",
                 flags & FE_UNDERFLOW ? "UNDERFLOW" : "",
                 flags & FE_DIVBYZERO ? "DIV0" : "",
                 flags & FE_INEXACT ? "INEXACT" : "",
                 flags & FE_INVALID ? "INVALID" : "");
    } else {
        snprintf(flag_str, sizeof(flag_str), "OK");
    }

    return flag_str;
}

static void print_double_number(int i, double num)
{
    uint64_t double_as_hex = *(uint64_t *) &num;
    int flags = fetestexcept(FE_ALL_EXCEPT);
    char *fstr = get_flag_state(flags);

    printf("%02d DOUBLE: %02.20e / %#020lx  (%#x => %s)\n",
           i, num, double_as_hex, flags, fstr);
}

static void print_single_number(int i, float num)
{
    uint32_t single_as_hex = *(uint32_t *) &num;
    int flags = fetestexcept(FE_ALL_EXCEPT);
    char *fstr = get_flag_state(flags);

    printf("%02d SINGLE: %02.20e / %#010x  (%#x => %s)\n",
           i, num, single_as_hex, flags, fstr);
}

static void print_half_number(int i, uint16_t num)
{
    int flags = fetestexcept(FE_ALL_EXCEPT);
    char *fstr = get_flag_state(flags);

    printf("%02d   HALF: %#010x  (%#x => %s)\n",
           i, num, flags, fstr);
}

float single_numbers[] = { -FLT_MAX, -FLT_MIN,
                           0.0,
                           FLT_MIN,
                           1.0, 2.0,
                           M_E, M_PI,
                           0x9EA82A22,
                           0xAB98FBA8,
                           FLT_MAX };

static void convert_single_to_half(void)
{
    int i;

    printf("Converting single-precision to half-precision\n");

    for (i = 0; i < ARRAY_SIZE(single_numbers); ++i) {
        float input = single_numbers[i];
        uint16_t output;

        feclearexcept(FE_ALL_EXCEPT);

        print_single_number(i, input);
        asm("fcvt %h0, %d1" : "=w" (output) : "x" (input));
        print_half_number(i, output);
    }
}

static void convert_single_to_double(void)
{
    int i;

    printf("Converting single-precision to double-precision\n");

    for (i = 0; i < ARRAY_SIZE(single_numbers); ++i) {
        float input = single_numbers[i];
        uint64_t output;

        feclearexcept(FE_ALL_EXCEPT);

        print_single_number(i, input);
        asm("fcvt %h0, %d1" : "=w" (output) : "x" (input));
        print_double_number(i, output);
    }
}

double double_numbers[] = { -DBL_MAX,
                            -2.0, -1.0,
                            -DBL_MIN,
                            0.0,
                            DBL_MIN,
                            1.0, 2.0,
                            M_E, M_PI,
                            0x9EA82A2287680UL,
                            0xAB98FBA843210UL,
                            DBL_MAX };

static void convert_double_to_half(void)
{
    int i;

    printf("Converting double-precision to half-precision\n");

    for (i = 0; i < ARRAY_SIZE(single_numbers); ++i) {
        double input = double_numbers[i];
        uint16_t output;

        feclearexcept(FE_ALL_EXCEPT);

        print_double_number(i, input);

        /* as we don't have _Float16 support */
        asm("fcvt %h0, %d1" : "=w" (output) : "x" (input));
        print_half_number(i, output);
    }
}

static void convert_double_to_single(void)
{
    int i;

    printf("Converting double-precision to single-precision\n");

    for (i = 0; i < ARRAY_SIZE(single_numbers); ++i) {
        double input = double_numbers[i];
        uint32_t output;

        feclearexcept(FE_ALL_EXCEPT);

        print_double_number(i, input);

        asm("fcvt %s0, %d1" : "=w" (output) : "x" (input));

        print_single_number(i, output);
    }
}

/* no handy defines for these numbers */
uint16_t half_numbers[] = {
    0xffff, /* -NaN / AHP -Max */
    0xfcff, /* -NaN / AHP */
    0xfc01, /* -NaN / AHP */
    0xfc00, /* -Inf */
    0xfbff, /* -Max */
    0xc000, /* -2 */
    0xbc00, /* -1 */
    0x8001, /* -MIN subnormal */
    0x8000, /* -0 */
    0x0000, /* +0 */
    0x0001, /* MIN subnormal */
    0x3c00, /* 1 */
    0x7bff, /* Max */
    0x7c00, /* Inf */
    0x7c01, /* NaN / AHP */
    0x7cff, /* NaN / AHP */
    0x7fff, /* NaN / AHP +Max*/
};

static void convert_half_to_double(void)
{
    int i;

    printf("Converting half-precision to double-precision\n");

    for (i = 0; i < ARRAY_SIZE(half_numbers); ++i) {
        uint16_t input = half_numbers[i];
        double output;

        feclearexcept(FE_ALL_EXCEPT);

        print_half_number(i, input);
        asm("fcvt %d0, %h1" : "=w" (output) : "x" (input));
        print_double_number(i, output);
    }
}

static void convert_half_to_single(void)
{
    int i;

    printf("Converting half-precision to single-precision\n");

    for (i = 0; i < ARRAY_SIZE(half_numbers); ++i) {
        uint16_t input = half_numbers[i];
        double output;

        feclearexcept(FE_ALL_EXCEPT);

        print_half_number(i, input);
        asm("fcvt %d0, %h1" : "=w" (output) : "x" (input));
        print_double_number(i, output);
    }
}

typedef struct {
    int flag;
    char *desc;
} float_mapping;

float_mapping round_flags[] =
{
    { FE_TONEAREST, "to nearest" },
    { FE_UPWARD, "upwards" },
    { FE_DOWNWARD, "downwards" },
    { FE_TOWARDZERO, "to zero" }
};

int main(int argc, char *argv[argc])
{
    int i;

    for (i = 0; i < ARRAY_SIZE(round_flags); ++i) {
        fesetround(round_flags[i].flag);
        printf("### Rounding %s\n", round_flags[i].desc);
        convert_single_to_half();
        convert_single_to_double();
        convert_double_to_half();
        convert_double_to_single();
        convert_half_to_single();
        convert_half_to_double();
    }

    /* And now with ARM alternative FP16 */
    asm("msr fpsr, x1\n\t"
        "orr x1, x1, %[flags]\n\t"
        "mrs x1, fpsr\n\t"
        : /* no output */ : [flags] "n" (1 << 26) : "x1" );

    printf("#### Enabling ARM Alternative Half Precision\n");

    for (i = 0; i < ARRAY_SIZE(round_flags); ++i) {
        fesetround(round_flags[i].flag);
        printf("### Rounding %s\n", round_flags[i].desc);
        convert_single_to_half();
        convert_single_to_double();
        convert_double_to_half();
        convert_double_to_single();
        convert_half_to_single();
        convert_half_to_double();
    }

    return 0;
}
