#include "config.h"
#ifndef HAVE_GETDELIM

#define GETDELIM_BUFFER 128

/* copied from xine-devel */
size_t
getdelim( char **lineptr, size_t *n, int delimiter, FILE *stream )
{
        char *p;
        int c;
        size_t len = 0;

        if (!lineptr || !n || (!*lineptr && *n))
                return -1;

        /* allocate initial buffer */
        if (!*lineptr || !*n) {
                char *np;
                np = realloc( *lineptr, GETDELIM_BUFFER );
                if (!np)
                        return -1;
                *n = GETDELIM_BUFFER;
                *lineptr = np;
        }

        p = *lineptr;

        /* read characters from stream */
        while ((c = fgetc( stream )) != EOF) {
                if (len >= *n) {
                        char *np = realloc( *lineptr, *n * 2 );
                        if (!np)
                                return -1;
                        p = np + (p - *lineptr);
                        *lineptr = np;
                        *n *= 2;
                }
                *p++ = (char) c;
                len++;
                if (delimiter == c)
                        break;
        }

        /* end of file without any bytes read */
        if ((c == EOF) && (len == 0))
                return -1;

        /* trailing "\0" */
        if (len >= *n) {
                char *np = realloc( *lineptr, *n + 1 );
                if (!np)
                        return -1;
                p = np + (p - *lineptr);
                *lineptr = np;
                *n += 1;
        }
        *p = '\0';

        return len;
}

#endif /* !HAVE_GETDELIM */
