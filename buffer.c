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
ldns_buffer_new(size_t capacity)
{
	ldns_buffer *buffer
		= MALLOC(ldns_buffer);
	if (!buffer) {
		return NULL;
	}
	
	buffer->_data = (uint8_t *) XMALLOC(uint8_t, capacity);
	if (!buffer->_data) {
		FREE(buffer);
		return NULL;
	}
	
	buffer->_position = 0;
	buffer->_limit = buffer->_capacity = capacity;
	buffer->_fixed = 0;
	ldns_buffer_invariant(buffer);
	
	return buffer;
}

void
ldns_buffer_new_from(ldns_buffer *buffer, void *data, size_t size)
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

bool
ldns_buffer_set_capacity(ldns_buffer *buffer, size_t capacity)
{
	void *data;
	
	ldns_buffer_invariant(buffer);
	assert(buffer->_position <= capacity);

	data = (uint8_t *) XREALLOC(buffer->_data, uint8_t, capacity);
	if (!data) {
		return false;
	} else {
		buffer->_data = data;
		buffer->_limit = buffer->_capacity = capacity;
		return true;
	}
}

bool
ldns_buffer_reserve(ldns_buffer *buffer, size_t amount)
{
	ldns_buffer_invariant(buffer);
	assert(!buffer->_fixed);
	if (buffer->_capacity < buffer->_position + amount) {
		size_t new_capacity = buffer->_capacity * 3 / 2;
		if (new_capacity < buffer->_position + amount) {
			new_capacity = buffer->_position + amount;
		}
		if (!ldns_buffer_set_capacity(buffer, new_capacity)) {
			return false;
		}
	}
	buffer->_limit = buffer->_capacity;
	return true;
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
	if (written == -1) {
		return -1;
	} else if ((size_t) written >= remaining) {
		if (!ldns_buffer_reserve(buffer, (size_t) written + 1)) {
			return -1;
		}
		va_start(args, format);
		written = vsnprintf((char *) ldns_buffer_current(buffer),
				    ldns_buffer_remaining(buffer),
				    format, args);
		va_end(args);
		if (written == -1) {
			return -1;
		}
	}
	buffer->_position += written;
	return written;
}

void
ldns_buffer_free(ldns_buffer *buffer)
{
	if (!buffer) {
		return;
	}

	if (!buffer->_fixed) {
		FREE(buffer->_data);
	}
	FREE(buffer);
}

void *
ldns_buffer_export(ldns_buffer *buffer)
{
	buffer->_fixed = 1;
	return buffer->_data;
}
