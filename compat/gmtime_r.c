#ifdef HAVE_CONFIG_H
#include <ldns/config.h>
#endif

#include <time.h>

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	/* no thread safety. */
	*result = *gmtime(timep);
	return result;
}
