/**
 * \file common.h
 *
 * Common definitions for LDNS
 */

/**
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#ifndef LDNS_COMMON_H
#define LDNS_COMMON_H

/*@ignore@*/
/* splint barfs on this construct */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# ifndef HAVE__BOOL
#  ifdef __cplusplus
typedef bool _Bool;
#  else
#   define _Bool signed char
#  endif
# endif
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif
/*@end@*/

#ifdef HAVE_ATTR_FORMAT
#define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */

#if defined(__cplusplus)
#define ATTR_UNUSED(x)
#elif defined(HAVE_ATTR_UNUSED)
#define ATTR_UNUSED(x)  x __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#define ATTR_UNUSED(x)  x
#endif /* !HAVE_ATTR_UNUSED */

#endif /* LDNS_COMMON_H */
