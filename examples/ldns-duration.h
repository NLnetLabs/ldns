/*
 * $Id: duration.h 4341 2011-01-31 15:21:09Z matthijs $
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

#ifndef LDNS_DURATION_H
#define LDNS_DURATION_H

#include <stdint.h>
#include <time.h>

/**
 * Duration.
 *
 */
typedef struct ldns_duration_struct ldns_duration_type;
struct ldns_duration_struct
{
    time_t years;
    time_t months;
    time_t weeks;
    time_t days;
    time_t hours;
    time_t minutes;
    time_t seconds;
};

/**
 * Create a new 'instant' duration.
 * \return ldns_duration_type* created duration
 *
 */
ldns_duration_type* ldns_duration_create(void);

/**
 * Compare durations.
 * \param[in] d1 one duration
 * \param[in] d2 another duration
 * \return int 0 if equal, -1 if d1 < d2, 1 if d2 < d1
 *
 */
int ldns_duration_compare(ldns_duration_type* d1, ldns_duration_type* d2);

/**
 * Create a duration from string.
 * \param[in] str string-format duration
 * \return ldns_duration_type* created duration
 *
 */
ldns_duration_type* ldns_duration_create_from_string(const char* str);

/**
 * Convert a duration to a string.
 * \param[in] duration duration to be converted
 * \return char* string-format duration
 *
 */
char* ldns_duration2string(ldns_duration_type* duration);

/**
 * Convert a duration to a time.
 * \param[in] duration duration to be converted
 * \return time_t time-format duration
 *
 */
time_t ldns_duration2time(ldns_duration_type* duration);

/**
 * Return a random time.
 * \param[in] mod modulo
 * \return time_t random time
 *
 */
time_t ods_rand(time_t mod);

/**
 * Return the shortest time.
 * \param[in] a one time
 * \param[in] b another time
 * \return time_t the shortest time
 *
 */
time_t time_minimum(time_t a, time_t b);

/**
 * Return the longest time.
 * \param[in] a one time
 * \param[in] b another time
 * \return time_t the shortest time
 *
 */
time_t time_maximum(time_t a, time_t b);

/**
 * Convert time into string.
 * \param[in] n time
 * \param[in] s string
 *
 */
void time_itoa(time_t n, char* s);

/**
 * Return time in datestamp.
 * \param[in] tt time
 * \param[in] format stamp format
 * \param[out] str store string
 * \return uint32_t integer based datestamp.
 *
 */
uint32_t time_datestamp(time_t tt, const char* format, char** str);

/**
 * Return the time since Epoch, measured in seconds.
 * If the timeshift is enabled, return the environment variable.
 * \return time_t now (or timeshift).
 *
 */
time_t time_now(void);

/**
 * Clean up duration.
 * \param[in] duration duration to be cleaned up
 *
 */
void ldns_duration_cleanup(ldns_duration_type* duration);

#endif /* LDNS_DURATION_H */
