/*
 * buffer.c -- generic memory buffer .
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <ldns/buffer.h>

ldns_buffer *
ldns_buffer_create(size_t capacity)
{
	ldns_buffer *buffer
		= MALLOC(ldns_buffer);
	if (!buffer)
		return NULL;
	
	buffer->_data = (uint8_t *) XMALLOC(uint8_t, capacity);
	buffer->_position = 0;
	buffer->_limit = buffer->_capacity = capacity;
	buffer->_fixed = 0;
	ldns_buffer_invariant(buffer);
	
	return buffer;
}

void
ldns_buffer_create_from(ldns_buffer *buffer, void *data, size_t size)
{
	assert(data != NULL);

	buffer->_position = 0;
	buffer->_limit = buffer->_capacity = size;
	buffer->_data = (uint8_t *) data;
	buffer->_fixed = 1;
	
	ldns_buffer_invariant(buffer);
}

void
ldns_buffer_clear(ldns_buffer *buffer)
{
	ldns_buffer_invariant(buffer);
	
	buffer->_position = 0;
	buffer->_limit = buffer->_capacity;
}

void
ldns_buffer_flip(ldns_buffer *buffer)
{
	ldns_buffer_invariant(buffer);
	
	buffer->_limit = buffer->_position;
	buffer->_position = 0;
}

void
ldns_buffer_rewind(ldns_buffer *buffer)
{
	ldns_buffer_invariant(buffer);
	
	buffer->_position = 0;
}

void
ldns_buffer_set_capacity(ldns_buffer *buffer, size_t capacity)
{
	ldns_buffer_invariant(buffer);
	assert(buffer->_position <= capacity);
	buffer->_data = (uint8_t *) XREALLOC(buffer->_data, uint8_t, capacity);
	buffer->_limit = buffer->_capacity = capacity;
}

void
ldns_buffer_reserve(ldns_buffer *buffer, size_t amount)
{
	ldns_buffer_invariant(buffer);
	assert(!buffer->_fixed);
	if (buffer->_capacity < buffer->_position + amount) {
		size_t new_capacity = buffer->_capacity * 3 / 2;
		if (new_capacity < buffer->_position + amount) {
			new_capacity = buffer->_position + amount;
		}
		ldns_buffer_set_capacity(buffer, new_capacity);
	}
	buffer->_limit = buffer->_capacity;
}

int
ldns_buffer_printf(ldns_buffer *buffer, const char *format, ...)
{
	va_list args;
	int written;
	size_t remaining;
	
	ldns_buffer_invariant(buffer);
	assert(buffer->_limit == buffer->_capacity);

	remaining = ldns_buffer_remaining(buffer);
	va_start(args, format);
	written = vsnprintf((char *) ldns_buffer_current(buffer), remaining,
			    format, args);
	va_end(args);
	if (written >= 0 && (size_t) written >= remaining) {
		ldns_buffer_reserve(buffer, (size_t) written + 1);
		va_start(args, format);
		written = vsnprintf((char *) ldns_buffer_current(buffer),
				    ldns_buffer_remaining(buffer),
				    format, args);
		va_end(args);
	}
	buffer->_position += written;
	return written;
}
