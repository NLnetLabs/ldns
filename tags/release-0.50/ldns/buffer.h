/*
 * buffer.h -- generic memory buffer.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 *
 * The buffer module implements a generic buffer.  The API is based on
 * the java.nio.Buffer interface.
 */

#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <assert.h>
#include <stdarg.h>
#include <string.h>

#include <ldns/error.h>
#include <ldns/common.h>

#include "ldns/util.h"

/**
 * number of initial bytes in buffer of
 * which we cannot tell the size before hand
 */
#define LDNS_MIN_BUFLEN	256

/**
 * LDNS implementation of buffers to ease operations
 */
struct buffer
{
	/** The current position used for reading/writing */ 
	size_t   _position;

	/** The read/write limit */
	size_t   _limit;

	/** The amount of data the buffer can contain */
	size_t   _capacity;

	/** The data contained in the buffer */
	uint8_t *_data;

	/** If the buffer is fixed it cannot be resized */
	unsigned _fixed : 1;

	/** The current state of the buffer */
	ldns_status _status;
};
typedef struct buffer ldns_buffer;


#ifdef NDEBUG
INLINE void
ldns_buffer_invariant(ldns_buffer *ATTR_UNUSED(buffer))
{
}
#else
INLINE void
ldns_buffer_invariant(ldns_buffer *buffer)
{
	assert(buffer != NULL);
	assert(buffer->_position <= buffer->_limit);
	assert(buffer->_limit <= buffer->_capacity);
	assert(buffer->_data != NULL);
}
#endif

/**
 * creates a new buffer with the specified capacity.
 *
 * \param[in] capacity the size (in bytes) to allocate for the buffer
 * \return the created buffer
 */
ldns_buffer *ldns_buffer_new(size_t capacity);

/**
 * creates a buffer with the specified data.  The data is not copied
 * and no memory allocations are done.  The buffer is fixed and cannot
 * be resized using buffer_reserve().
 *
 * \param[in] buffer pointer to the buffer to put the data in
 * \param[in] data the data to encapsulate in the buffer
 * \param[in] size the size of the data
 */
void ldns_buffer_new_frm_data(ldns_buffer *buffer, void *data, size_t size);

/**
 * clears the buffer and make it ready for writing.  The buffer's limit
 * is set to the capacity and the position is set to 0.
 */
void ldns_buffer_clear(ldns_buffer *buffer);

/**
 * makes the buffer ready for reading the data that has been written to
 * the buffer.  The buffer's limit is set to the current position and
 * the position is set to 0.
 *
 * \param[in] buffer the buffer to flip
 * \return void
 */
void ldns_buffer_flip(ldns_buffer *buffer);

/**
 * make the buffer ready for re-reading the data.  The buffer's
 * position is reset to 0.
 */
void ldns_buffer_rewind(ldns_buffer *buffer);

/**
 * returns the current position in the buffer (as a number of bytes)
 */
INLINE size_t
ldns_buffer_position(ldns_buffer *buffer)
{
	return buffer->_position;
}

/**
 * sets the buffer's position to MARK.  The position must be less than
 * or equal to the buffer's limit.
 */
INLINE void
ldns_buffer_set_position(ldns_buffer *buffer, size_t mark)
{
	assert(mark <= buffer->_limit);
	buffer->_position = mark;
}

/**
 * changes the buffer's position by COUNT bytes.  The position must not
 * be moved behind the buffer's limit or before the beginning of the
 * buffer.
 */
INLINE void
ldns_buffer_skip(ldns_buffer *buffer, ssize_t count)
{
	assert(buffer->_position + count <= buffer->_limit);
	buffer->_position += count;
}

/**
 * returns the maximum size of the buffer
 */
INLINE size_t
ldns_buffer_limit(ldns_buffer *buffer)
{
	return buffer->_limit;
}

/**
 * changes the buffer's limit.  If the buffer's position is greater
 * than the new limit the position is set to the limit.
 */
INLINE void
ldns_buffer_set_limit(ldns_buffer *buffer, size_t limit)
{
	assert(limit <= buffer->_capacity);
	buffer->_limit = limit;
	if (buffer->_position > buffer->_limit)
		buffer->_position = buffer->_limit;
}

/**
 * returns the number of bytes the buffer can hold.
 */
INLINE size_t
ldns_buffer_capacity(ldns_buffer *buffer)
{
	return buffer->_capacity;
}

/**
 * changes the buffer's capacity.  The data is reallocated so any
 * pointers to the data may become invalid.  The buffer's limit is set
 * to the buffer's new capacity.
 */
bool ldns_buffer_set_capacity(ldns_buffer *buffer, size_t capacity);

/**
 * ensures BUFFER can contain at least AMOUNT more bytes.  The buffer's
 * capacity is increased if necessary using buffer_set_capacity().
 *
 * The buffer's limit is always set to the (possibly increased)
 * capacity.
 */
bool ldns_buffer_reserve(ldns_buffer *buffer, size_t amount);

/**
 * returns a pointer to the data at the indicated position.
 */
INLINE uint8_t *
ldns_buffer_at(ldns_buffer *buffer, size_t at)
{
	assert(at <= buffer->_limit);
	return buffer->_data + at;
}

/**
 * returns a pointer to the beginning of the buffer (the data at
 * position 0).
 */
INLINE uint8_t *
ldns_buffer_begin(ldns_buffer *buffer)
{
	return ldns_buffer_at(buffer, 0);
}

/**
 * returns a pointer to the end of the buffer (the data at the buffer's
 * limit).
 */
INLINE uint8_t *
ldns_buffer_end(ldns_buffer *buffer)
{
	return ldns_buffer_at(buffer, buffer->_limit);
}

/**
 * returns a pointer to the data at the buffer's current position.
 */
INLINE uint8_t *
ldns_buffer_current(ldns_buffer *buffer)
{
	return ldns_buffer_at(buffer, buffer->_position);
}

/**
 * returns the number of bytes remaining between the indicated position and
 * the limit.
 */
INLINE size_t
ldns_buffer_remaining_at(ldns_buffer *buffer, size_t at)
{
	ldns_buffer_invariant(buffer);
	assert(at <= buffer->_limit);
	return buffer->_limit - at;
}

/**
 * returns the number of bytes remaining between the buffer's position and
 * limit.
 */
INLINE size_t
ldns_buffer_remaining(ldns_buffer *buffer)
{
	return ldns_buffer_remaining_at(buffer, buffer->_position);
}

/**
 * checks if the buffer has at least COUNT more bytes available.
 * Before reading or writing the caller needs to ensure enough space
 * is available!
 */
INLINE int
ldns_buffer_available_at(ldns_buffer *buffer, size_t at, size_t count)
{
	return count <= ldns_buffer_remaining_at(buffer, at);
}

/**
 * checks if the buffer has count bytes available at the current position
 */
INLINE int
ldns_buffer_available(ldns_buffer *buffer, size_t count)
{
	return ldns_buffer_available_at(buffer, buffer->_position, count);
}

/**
 * writes the given data to the buffer at the specified position
 *
 * \param[in] at the position (in number of bytes) to write the data at
 * \param[in] data pointer to the data to write to the buffer
 * \param[in] count the number of bytes of data to write
 */
INLINE void
ldns_buffer_write_at(ldns_buffer *buffer, size_t at, const void *data, size_t count)
{
	assert(ldns_buffer_available_at(buffer, at, count));
	memcpy(buffer->_data + at, data, count);
}

/**
 * writes count bytes of data to the current position of the buffer
 */
INLINE void
ldns_buffer_write(ldns_buffer *buffer, const void *data, size_t count)
{
	ldns_buffer_write_at(buffer, buffer->_position, data, count);
	buffer->_position += count;
}

/**
 * copies the given (null-delimited) string to the specified position at the buffer
 */
INLINE void
ldns_buffer_write_string_at(ldns_buffer *buffer, size_t at, const char *str)
{
	ldns_buffer_write_at(buffer, at, str, strlen(str));
}

/**
 * copies the given (null-delimited) string to the current position at the buffer
 */
INLINE void
ldns_buffer_write_string(ldns_buffer *buffer, const char *str)
{
	ldns_buffer_write(buffer, str, strlen(str));
}

/**
 * writes the given byte of data at the given position in the buffer
 */
INLINE void
ldns_buffer_write_u8_at(ldns_buffer *buffer, size_t at, uint8_t data)
{
	assert(ldns_buffer_available_at(buffer, at, sizeof(data)));
	buffer->_data[at] = data;
}

/**
 * writes the given byte of data at the current position in the buffer
 */
INLINE void
ldns_buffer_write_u8(ldns_buffer *buffer, uint8_t data)
{
	ldns_buffer_write_u8_at(buffer, buffer->_position, data);
	buffer->_position += sizeof(data);
}

/**
 * writes the given 2 byte integer at the given position in the buffer
 */
INLINE void
ldns_buffer_write_u16_at(ldns_buffer *buffer, size_t at, uint16_t data)
{
	assert(ldns_buffer_available_at(buffer, at, sizeof(data)));
	write_uint16(buffer->_data + at, data);
}

/**
 * writes the given 2 byte integer at the current position in the buffer
 */
INLINE void
ldns_buffer_write_u16(ldns_buffer *buffer, uint16_t data)
{
	ldns_buffer_write_u16_at(buffer, buffer->_position, data);
	buffer->_position += sizeof(data);
}

/**
 * writes the given 4 byte integer at the given position in the buffer
 */
INLINE void
ldns_buffer_write_u32_at(ldns_buffer *buffer, size_t at, uint32_t data)
{
	assert(ldns_buffer_available_at(buffer, at, sizeof(data)));
	write_uint32(buffer->_data + at, data);
}

/**
 * writes the given 4 byte integer at the current position in the buffer
 */
INLINE void
ldns_buffer_write_u32(ldns_buffer *buffer, uint32_t data)
{
	ldns_buffer_write_u32_at(buffer, buffer->_position, data);
	buffer->_position += sizeof(data);
}

/**
 * copies count bytes of data at the given position to the given data-array
 */
INLINE void
ldns_buffer_read_at(ldns_buffer *buffer, size_t at, void *data, size_t count)
{
	assert(ldns_buffer_available_at(buffer, at, count));
	memcpy(data, buffer->_data + at, count);
}

/**
 * copies count bytes of data at the current position to the given data-array
 */
INLINE void
ldns_buffer_read(ldns_buffer *buffer, void *data, size_t count)
{
	ldns_buffer_read_at(buffer, buffer->_position, data, count);
	buffer->_position += count;
}

/**
 * returns the byte value at the given position in the buffer
 */
INLINE uint8_t
ldns_buffer_read_u8_at(ldns_buffer *buffer, size_t at)
{
	assert(ldns_buffer_available_at(buffer, at, sizeof(uint8_t)));
	return buffer->_data[at];
}

/**
 * returns the byte value at the current position in the buffer
 */
INLINE uint8_t
ldns_buffer_read_u8(ldns_buffer *buffer)
{
	uint8_t result = ldns_buffer_read_u8_at(buffer, buffer->_position);
	buffer->_position += sizeof(uint8_t);
	return result;
}

/**
 * returns the 2-byte integer value at the given position in the buffer
 */
INLINE uint16_t
ldns_buffer_read_u16_at(ldns_buffer *buffer, size_t at)
{
	assert(ldns_buffer_available_at(buffer, at, sizeof(uint16_t)));
	return read_uint16(buffer->_data + at);
}

/**
 * returns the 2-byte integer value at the current position in the buffer
 */
INLINE uint16_t
ldns_buffer_read_u16(ldns_buffer *buffer)
{
	uint16_t result = ldns_buffer_read_u16_at(buffer, buffer->_position);
	buffer->_position += sizeof(uint16_t);
	return result;
}

/**
 * returns the 4-byte integer value at the given position in the buffer
 */
INLINE uint32_t
ldns_buffer_read_u32_at(ldns_buffer *buffer, size_t at)
{
	assert(ldns_buffer_available_at(buffer, at, sizeof(uint32_t)));
	return read_uint32(buffer->_data + at);
}

/**
 * returns the 4-byte integer value at the current position in the buffer
 */
INLINE uint32_t
ldns_buffer_read_u32(ldns_buffer *buffer)
{
	uint32_t result = ldns_buffer_read_u32_at(buffer, buffer->_position);
	buffer->_position += sizeof(uint32_t);
	return result;
}

/**
 * returns the status of the buffer
 */
INLINE ldns_status
ldns_buffer_status(ldns_buffer *buffer)
{
	return buffer->_status;
}

/**
 * returns true if the status of the buffer is LDNS_STATUS_OK, false otherwise
 */
INLINE bool
ldns_buffer_status_ok(ldns_buffer *buffer)
{
	if (buffer) {
		return ldns_buffer_status(buffer) == LDNS_STATUS_OK;
	} else {
		return false;
	}
}

/**
 * prints to the buffer, increasing the capacity if required using
 * buffer_reserve(). The buffer's position is set to the terminating
 * '\0'. Returns the number of characters written (not including the
 * terminating '\0') or -1 on failure.
 */
int ldns_buffer_printf(ldns_buffer *buffer, const char *format, ...);
/*	ATTR_FORMAT(printf, 2, 3);*/

/**
 * frees the buffer.
 * \param[in] *buffer the buffer to be freed
 * \return void
 */
void ldns_buffer_free(ldns_buffer *buffer);

/**
 * Makes the buffer fixed and returns a pointer to the data.  The
 * caller is responsible for free'ing the result.
 * \param[in] *buffer the buffer to be exported
 * \return void
 */
void *ldns_buffer_export(ldns_buffer *buffer);

#endif /* _BUFFER_H_ */
