/* Just a replacement, if the original isascii is not
   present */

#if HAVE_CONFIG_H
#include <ldns/config.h>
#endif

int isascii(int c);

/* true if character is a blank (space or tab). C99. */
int
isascii(int c)
{
	return c >= 0 && c < 128;
}
