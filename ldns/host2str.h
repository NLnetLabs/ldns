
#ifndef _LDNS_HOST2STR_H
#define _LDNS_HOST2STR_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ctype.h>

#include "util.h"

/**
 * Converts the data in the rdata field to presentation
 * format (as char *) and appends it to the given buffer
 *
 * @param output pointer to the buffer to append the data to
 * @param rdf the pointer to the rdafa field containing the data
 * @return status
 */
ldns_status ldns_rdf2buffer_str(ldns_buffer *output, ldns_rdf *rdf);

/**
 * Converts the data in the resource record to presentation
 * format (as char *) and appends it to the given buffer
 *
 * @param output pointer to the buffer to append the data to
 * @param rdf the pointer to the rdafa field containing the data
 * @return status
 */
ldns_status ldns_rr2buffer_str(ldns_buffer *output, ldns_rr *rr);

/**
 * Converts the data in the DNS packet to presentation
 * format (as char *) and appends it to the given buffer
 *
 * @param output pointer to the buffer to append the data to
 * @param rdf the pointer to the rdafa field containing the data
 * @return status
 */
ldns_status ldns_pkt2buffer_str(ldns_buffer *output, ldns_pkt *pkt);

/**
 * Converts the data in the int16 typed rdata field to presentation
 * format (as char *) and appends it to the given buffer
 *
 * @param output pointer to the buffer to append the data to
 * @param rdf the pointer to the rdafa field containing the data
 * @return status
 */
ldns_status ldns_rdf2buffer_str_int16(ldns_buffer *output, ldns_rdf *rdf);

/**
 * Converts the data in the rdata field to presentation format and
 * returns that as a char *.
 * Remeber to free it
 *
 * @param rdf The rdata field to convert
 * @return null terminated char * data, or NULL on error
 */
char *ldns_rdf2str(ldns_rdf *rdf);

/**
 * Converts the data in the resource record to presentation format and
 * returns that as a char *.
 * Remeber to free it
 *
 * @param rr The rdata field to convert
 * @return null terminated char * data, or NULL on error
 */
char *ldns_rr2str(ldns_rr *rr);

/**
 * Converts the data in the DNS packet to presentation format and
 * returns that as a char *.
 * Remeber to free it
 *
 * @param pkt The rdata field to convert
 * @return null terminated char * data, or NULL on error
 */
char *ldns_pkt2str(ldns_pkt *pkt);

/**
 * Returns the data in the buffer as a null terminated char * string
 * Buffer data must be char * type
 *
 * @param buffer buffer containing char * data
 * @return null terminated char * data, or NULL on error
 */
char *buffer2str(ldns_buffer *buffer);

/**
 * Prints the data in the rdata field to the given file stream
 * (in presentation format)
 *
 * @param output the file stream to print to
 * @param rdf the rdata field to print
 */
void ldns_rdf_print(FILE *output, ldns_rdf *rdf);

/**
 * Prints the data in the rresource record to the given file stream
 * (in presentation format)
 *
 * @param output the file stream to print to
 * @param rdf the resource record to print
 */
void ldns_rr_print(FILE *output, ldns_rr *rr);

/**
 * Prints the data in the DNS packet to the given file stream
 * (in presentation format)
 *
 * @param output the file stream to print to
 * @param pkt the packet to print
 */
void ldns_pkt_print(FILE *output, ldns_pkt *pkt);

#endif
