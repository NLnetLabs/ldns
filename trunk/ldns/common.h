/*
 * common.h
 *
 * Common definitions for LDNS
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_COMMON_H
#define _LDNS_COMMON_H

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else

#ifndef __cplusplus

typedef unsigned char bool;
#define false 0
#define true  1

#endif /* !__cplusplus */

#endif /* !HAVE_STDBOOL_H */

#endif /* !_LDNS_COMMON_H */
