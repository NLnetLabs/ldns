/*
 * cpuinfo.c -- functions for processor capabilities
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <ldns/config.h>
#include <ldns/cpuinfo.h>

#if defined(LDNS_GCC_CPUID_AVAILABLE)
# include <cpuid.h>
#endif

#if defined(LDNS_MSVC_CPUID_AVAILABLE)
# include <intrin.h>
#endif

#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

static int
ldns_cpuid(int func, int subfunc, unsigned int* a, unsigned int* b, unsigned int* c, unsigned int* d)
{
#if defined(LDNS_GCC_CPUID_AVAILABLE)
    return __get_cpuid_count(func, subfunc, a, b, c, d);
#elif defined(LDNS_MSVC_CPUID_AVAILABLE)
    int reg[4];
    __cpuidex(reg, 0, 0);
    if (func > reg[0]) { return 0; }
    __cpuidex(reg, func, subfunc);
    *a = reg[0]; *b = reg[1]; *c = reg[2]; *d = reg[3];
    return 1;
#elif defined(__GNUC__)
    int reg[4];
    __asm__
    (
        // save ebx in case -fPIC is being used
# if defined(__x86_64__) || defined(__amd64__)
        "pushq %%rbx; cpuid; mov %%ebx, %%edi; popq %%rbx"
# else
        "push %%ebx; cpuid; mov %%ebx, %%edi; pop %%ebx"
# endif
        : "=a" (reg[0]), "=D" (reg[1]), "=c" (reg[2]), "=d" (reg[3])
        : "a" (0), "c" (0)
        : "cc"
    );
    if (func > reg[0]) { return 0; }
    __asm__
    (
        // save ebx in case -fPIC is being used
# if defined(__x86_64__) || defined(__amd64__)
        "pushq %%rbx; cpuid; mov %%ebx, %%edi; popq %%rbx"
# else
        "push %%ebx; cpuid; mov %%ebx, %%edi; pop %%ebx"
# endif
        : "=a" (reg[0]), "=D" (reg[1]), "=c" (reg[2]), "=d" (reg[3])
        : "a" (func), "c" (subfunc)
        : "cc"
    );
    *a = reg[0]; *b = reg[1]; *c = reg[2]; *d = reg[3];
    return 1;
#else
    return 0;
#endif
}

static int
ldns_cpu_x86_sha(void)
{
    static int sha_feature = -1;

    if (sha_feature == -1)
    {
        /* Default feature, off */
        int temp_sha_feature = 0;

        /* SSE2: verify the cpu supports SSE2; XSAVE: verify the cpu supports XSAVE  */
        /* OSXSAVE: verify the OS supports XSAVE; SHA: verify the cpu supports SHA   */
        enum { SSE2_FLAG = 1<<26, XSAVE_FLAG = 1<<26, OSXSAVE_FLAG = 1<<27, SHA_FLAG = 1<<29 };
        unsigned int a, b, c, d;

        if (ldns_cpuid(0, 0, &a, &b, &c, &d) && a >= 7)
        {
            /* Check XSAVE and OSXSAVE for legacy i386 and i586 hardware. The checks */
            /* have not been needed in practice since about the year 2000 or so.     */
            if (ldns_cpuid(1, 0, &a, &b, &c, &d) && (d & SSE2_FLAG) == SSE2_FLAG &&
               (c & XSAVE_FLAG) == XSAVE_FLAG && (c & OSXSAVE_FLAG) == OSXSAVE_FLAG)
            {
                if (ldns_cpuid(7, 0, &a, &b, &c, &d) && (b & SHA_FLAG) == SHA_FLAG)
                {
                    temp_sha_feature = 1;
                }
            }
        }

        if (sha_feature == -1)
        {
            sha_feature = temp_sha_feature;
        }
    }

    /* Returns 1 if SHA is available, 0 otherwise */
    return sha_feature;
}

int
ldns_cpu_x86_sha1(void)
{
    /* Returns 1 if SHA is available, 0 otherwise */
    return ldns_cpu_x86_sha();
}

int
ldns_cpu_x86_sha256(void)
{
    /* Returns 1 if SHA is available, 0 otherwise */
    return ldns_cpu_x86_sha();
}
