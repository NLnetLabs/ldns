/*
 * cpuinfo.h -- functions for processor capabilities
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef LDNS_CPUINFO_H
#define LDNS_CPUINFO_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Determine if a x86 processor supports SHA-1 extensions
 *
 * \return 1 if a x86 processor supports SHA-1 extensions, 0 otherwise.
 *
 * \note non-x86 processors return 0.
 */
int ldns_cpu_x86_sha1(void);

/**
 * Determine if a x86 processor supports SHA-256 extensions
 *
 * \return 1 if a x86 processor supports SHA-256 extensions, 0 otherwise.
 *
 * \note non-x86 processors return 0.
 */
int ldns_cpu_x86_sha256(void);

#ifdef __cplusplus
}
#endif

#endif  /* LDNS_CPUINFO_H */
