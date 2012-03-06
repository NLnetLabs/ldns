/*
 * $Id: duration.c 4518 2011-02-24 15:39:09Z matthijs $
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 *
 * This file is copied from the OpenDNSSEC source repository
 * and only slightly adapted to make it fit.
 */

/**
 *
 * Durations.
 */

#include "ldns-duration.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/**
 * Create a new 'instant' duration.
 *
 */
ldns_duration_type*
ldns_duration_create(void)
{
    ldns_duration_type* duration;

    duration = malloc(sizeof(ldns_duration_type));
    if (!duration) {
        return NULL;
    }
    duration->years = 0;
    duration->months = 0;
    duration->weeks = 0;
    duration->days = 0;
    duration->hours = 0;
    duration->minutes = 0;
    duration->seconds = 0;
    return duration;
}


/**
 * Compare durations.
 *
 */
int
ldns_duration_compare(ldns_duration_type* d1, ldns_duration_type* d2)
{
    if (!d1 && !d2) {
        return 0;
    }
    if (!d1 || !d2) {
        return d1?-1:1;
    }

    if (d1->years != d2->years) {
        return d1->years - d2->years;
    }
    if (d1->months != d2->months) {
        return d1->months - d2->months;
    }
    if (d1->weeks != d2->weeks) {
        return d1->weeks - d2->weeks;
    }
    if (d1->days != d2->days) {
        return d1->days - d2->days;
    }
    if (d1->hours != d2->hours) {
        return d1->hours - d2->hours;
    }
    if (d1->minutes != d2->minutes) {
        return d1->minutes - d2->minutes;
    }
    if (d1->seconds != d2->seconds) {
        return d1->seconds - d2->seconds;
    }

    return 0;
}


/**
 * Create a duration from string.
 *
 */
ldns_duration_type*
ldns_duration_create_from_string(const char* str)
{
    ldns_duration_type* duration = ldns_duration_create();
    char* P, *X, *T, *W;
    int not_weeks = 0;

    if (!duration) {
        return NULL;
    }
    if (!str) {
        return duration;
    }

    P = strchr(str, 'P');
    if (!P) {
	ldns_duration_cleanup(duration);
        return NULL;
    }

    T = strchr(str, 'T');
    X = strchr(str, 'Y');
    if (X) {
        duration->years = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'M');
    if (X && (!T || (size_t) (X-P) < (size_t) (T-P))) {
        duration->months = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'D');
    if (X) {
        duration->days = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    if (T) {
        str = T;
        not_weeks = 1;
    }
    X = strchr(str, 'H');
    if (X && T) {
        duration->hours = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strrchr(str, 'M');
    if (X && T && (size_t) (X-P) > (size_t) (T-P)) {
        duration->minutes = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'S');
    if (X && T) {
        duration->seconds = atoi(str+1);
        str = X;
        not_weeks = 1;
    }

    W = strchr(str, 'W');
    if (W) {
        if (not_weeks) {
            ldns_duration_cleanup(duration);
            return NULL;
        } else {
            duration->weeks = atoi(str+1);
            str = W;
        }
    }
    return duration;
}


/**
 * Get the number of digits in a number.
 *
 */
static size_t
digits_in_number(time_t duration)
{
    uint32_t period = (uint32_t) duration;
    size_t count = 0;

    while (period > 0) {
        count++;
        period /= 10;
    }
    return count;
}


/**
 * Convert a duration to a string.
 *
 */
char*
ldns_duration2string(ldns_duration_type* duration)
{
    char* str = NULL, *num = NULL;
    size_t count = 2;
    int T = 0;

    if (!duration) {
        return NULL;
    }

    if (duration->years > 0) {
        count = count + 1 + digits_in_number(duration->years);
    }
    if (duration->months > 0) {
        count = count + 1 + digits_in_number(duration->months);
    }
    if (duration->weeks > 0) {
        count = count + 1 + digits_in_number(duration->weeks);
    }
    if (duration->days > 0) {
        count = count + 1 + digits_in_number(duration->days);
    }
    if (duration->hours > 0) {
        count = count + 1 + digits_in_number(duration->hours);
        T = 1;
    }
    if (duration->minutes > 0) {
        count = count + 1 + digits_in_number(duration->minutes);
        T = 1;
    }
    if (duration->seconds > 0) {
        count = count + 1 + digits_in_number(duration->seconds);
        T = 1;
    }
    if (T) {
        count++;
    }

    str = (char*) calloc(count, sizeof(char));
    str[0] = 'P';
    str[1] = '\0';

    if (duration->years > 0) {
        count = digits_in_number(duration->years);
        num = (char*) calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uY", (uint32_t) duration->years);
        str = strncat(str, num, count+2);
        free((void*) num);
    }
    if (duration->months > 0) {
        count = digits_in_number(duration->months);
        num = (char*) calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uM", (uint32_t) duration->months);
        str = strncat(str, num, count+2);
        free((void*) num);
    }
    if (duration->weeks > 0) {
        count = digits_in_number(duration->weeks);
        num = (char*) calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uW", (uint32_t) duration->weeks);
        str = strncat(str, num, count+2);
        free((void*) num);
    }
    if (duration->days > 0) {
        count = digits_in_number(duration->days);
        num = (char*) calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uD", (uint32_t) duration->days);
        str = strncat(str, num, count+2);
        free((void*) num);
    }
    if (T) {
        str = strncat(str, "T", 1);
    }
    if (duration->hours > 0) {
        count = digits_in_number(duration->hours);
        num = (char*) calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uH", (uint32_t) duration->hours);
        str = strncat(str, num, count+2);
        free((void*) num);
    }
    if (duration->minutes > 0) {
        count = digits_in_number(duration->minutes);
        num = (char*) calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uM", (uint32_t) duration->minutes);
        str = strncat(str, num, count+2);
        free((void*) num);
    }
    if (duration->seconds > 0) {
        count = digits_in_number(duration->seconds);
        num = (char*) calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uS", (uint32_t) duration->seconds);
        str = strncat(str, num, count+2);
        free((void*) num);
    }
    return str;
}


/**
 * Convert a duration to a time.
 *
 */
time_t
ldns_duration2time(ldns_duration_type* duration)
{
    time_t period = 0;
    char* dstr = NULL;

    if (duration) {
        period += (duration->seconds);
        period += (duration->minutes)*60;
        period += (duration->hours)*3600;
        period += (duration->days)*86400;
        period += (duration->weeks)*86400*7;
        period += (duration->months)*86400*31;
        period += (duration->years)*86400*365;

        /* [TODO] calculate correct number of days in this month/year */
	/*
        if (duration->months || duration->years) {
        }
	*/
    }
    return period;
}

/**
 * Return the shortest time.
 *
 */
time_t
time_minimum(time_t a, time_t b)
{
    return (a < b ? a : b);
}

/**
 * Return the longest time.
 *
 */
time_t
time_maximum(time_t a, time_t b)
{
    return (a > b ? a : b);
}


/**
 * Return a random time.
 *
 */
time_t
ods_rand(time_t mod)
{
#ifdef HAVE_ARC4RANDOM_UNIFORM
    return (time_t) (arc4random_uniform((uint32_t) mod+1));
#elif HAVE_ARC4RANDOM
    return (time_t) (arc4random() % (unsigned) mod+1);
#else
    return (time_t) (random() % (unsigned) mod+1);
#endif
}


/* Number of days per month (except for February in leap years). */
static const int mdays[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};


static int
is_leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}


static int
leap_days(int y1, int y2)
{
    --y1;
    --y2;
    return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}


/*
 * Code taken from NSD 3.2.5, which is
 * code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
static time_t
mktime_from_utc(const struct tm *tm)
{
    int year = 1900 + tm->tm_year;
    time_t days = 365 * (year - 1970) + leap_days(1970, year);
    time_t hours;
    time_t minutes;
    time_t seconds;
    int i;

    for (i = 0; i < tm->tm_mon; ++i) {
        days += mdays[i];
    }
    if (tm->tm_mon > 1 && is_leap_year(year)) {
        ++days;
    }
    days += tm->tm_mday - 1;

    hours = days * 24 + tm->tm_hour;
    minutes = hours * 60 + tm->tm_min;
    seconds = minutes * 60 + tm->tm_sec;

    return seconds;
}


/**
 * Convert time in string format into seconds.
 *
 */
static time_t
timeshift2time(const char *time)
{
        /* convert a string in format YYMMDDHHMMSS to time_t */
        struct tm tm;
        time_t timeshift = 0;

        /* Try to scan the time... */
        if (strptime(time, "%Y%m%d%H%M%S", &tm)) {
                timeshift = mktime_from_utc(&tm);
	}
        return timeshift;
}


/**
 * Return the time since Epoch, measured in seconds.
 *
 */
time_t
time_now(void)
{
#ifdef ENFORCER_TIMESHIFT
    const char* env = getenv("ENFORCER_TIMESHIFT");
    if (env) {
        return timeshift2time(env);
    } else
#endif /* ENFORCER_TIMESHIFT */

    return time(NULL);
}


/**
 * copycode: This code is based on the EXAMPLE in the strftime manual.
 *
 */
uint32_t
time_datestamp(time_t tt, const char* format, char** str)
{
    time_t t;
    struct tm *tmp;
    uint32_t ut = 0;
    char outstr[32];

    if (tt) {
        t = tt;
    } else {
        t = time_now();
    }

    tmp = localtime(&t);
    if (tmp == NULL) {
        return 0;
    }

    if (strftime(outstr, sizeof(outstr), format, tmp) == 0) {
        return 0;
    }

    ut = (uint32_t) strtoul(outstr, NULL, 10);
    if (str) {
        *str = strdup(outstr);
    }
    return ut;
}

static void
time_itoa_reverse(char* s)
{
    int i, j;
    char c;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
    return;
}


/**
 * Convert time into string.
 *
 */
void
time_itoa(time_t n, char* s)
{
    int i = 0;

    do {       /* generate digits in reverse order */
        s[i++] = n % 10 + '0';   /* get next digit */
    } while ((n /= 10) > 0);     /* delete it */
    s[i] = '\0';
    time_itoa_reverse(s);
    return;
}


/**
 * Clean up duration.
 *
 */
void
ldns_duration_cleanup(ldns_duration_type* duration)
{
    if (!duration) {
        return;
    }
    free(duration);
    return;
}
