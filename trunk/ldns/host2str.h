
#ifndef _LDNS_HOST2STR_H
#define _LDNS_HOST2STR_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ldns/resolver.h>
#include <ctype.h>

#include "util.h"

/** 
 * Converts an LDNS_RDF_TYPE_A rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_a(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_AAAA rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_aaaa(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_STR rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_str(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_B64 rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_b64(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_HEX rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_hex(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_TYPE rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_type(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_CLASS rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_class(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_ALG rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_alg(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_CERT rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_cert(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_LOC rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_loc(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_UNKNOWN rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_unknown(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_NSAP rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_nsap(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_WKS rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_wks(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_NSEC rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_nsec(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_PERIOD rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_period(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_TSIGTIME rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_tsigtime(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_APL rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_apl(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_TODO rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_todo(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_INT16_DATA rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_int16_data(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_IPSECKEY rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_ipseckey(ldns_buffer *output, ldns_rdf *rdf);

/** 
 * Converts an LDNS_RDF_TYPE_TSIG rdata element to string format and adds it to the output buffer 
 * \param[in] *rdf The rdata to convert
 * \param[in] *output The buffer to add the data to
 * \return LDNS_STATUS_OK on success, and error status on failure
 */
ldns_status ldns_rdf2buffer_str_tsig(ldns_buffer *output, ldns_rdf *rdf);


/**
 * Converts the data in the rdata field to presentation
 * format (as char *) and appends it to the given buffer
 *
 * \param[in] output pointer to the buffer to append the data to
 * \param[in] rdf the pointer to the rdafa field containing the data
 * \return status
 */
ldns_status ldns_rdf2buffer_str(ldns_buffer *output, ldns_rdf *rdf);

/**
 * Converts the data in the resource record to presentation
 * format (as char *) and appends it to the given buffer
 *
 * \param[in] output pointer to the buffer to append the data to
 * \param[in] rr the pointer to the rr field to convert
 * \return status
 */
ldns_status ldns_rr2buffer_str(ldns_buffer *output, ldns_rr *rr);

/**
 * Converts the data in the DNS packet to presentation
 * format (as char *) and appends it to the given buffer
 *
 * \param[in] output pointer to the buffer to append the data to
 * \param[in] pkt the pointer to the packet to convert
 * \return status
 */
ldns_status ldns_pkt2buffer_str(ldns_buffer *output, ldns_pkt *pkt);

/**
 * Converts the data in the int16 typed rdata field to presentation
 * format (as char *) and appends it to the given buffer
 *
 * \param[in] output pointer to the buffer to append the data to
 * \param[in] rdf the pointer to the rdafa field containing the data
 * \return status
 */
ldns_status ldns_rdf2buffer_str_int16(ldns_buffer *output, ldns_rdf *rdf);

/**
 * Converts the data in the rdata field to presentation format and
 * returns that as a char *.
 * Remember to free it.
 *
 * \param[in] rdf The rdata field to convert
 * \return null terminated char * data, or NULL on error
 */
char *ldns_rdf2str(ldns_rdf *rdf);

/**
 * Converts the data in the resource record to presentation format and
 * returns that as a char *.
 * Remember to free it.
 *
 * \param[in] rr The rdata field to convert
 * \return null terminated char * data, or NULL on error
 */
char *ldns_rr2str(ldns_rr *rr);

/**
 * Converts the data in the DNS packet to presentation format and
 * returns that as a char *.
 * Remember to free it.
 *
 * \param[in] pkt The rdata field to convert
 * \return null terminated char * data, or NULL on error
 */
char *ldns_pkt2str(ldns_pkt *pkt);

/**
 * Returns the data in the buffer as a null terminated char * string
 * Buffer data must be char * type
 *
 * \param[in] buffer buffer containing char * data
 * \return null terminated char * data, or NULL on error
 */
char *buffer2str(ldns_buffer *buffer);

/**
 * Prints the data in the rdata field to the given file stream
 * (in presentation format)
 *
 * \param[in] output the file stream to print to
 * \param[in] rdf the rdata field to print
 * \return void
 */
void ldns_rdf_print(FILE *output, ldns_rdf *rdf);

/**
 * Prints the data in the resource record to the given file stream
 * (in presentation format)
 *
 * \param[in] output the file stream to print to
 * \param[in] rr the resource record to print
 * \return void
 */
void ldns_rr_print(FILE *output, ldns_rr *rr);

/**
 * Prints the data in the DNS packet to the given file stream
 * (in presentation format)
 *
 * \param[in] output the file stream to print to
 * \param[in] pkt the packet to print
 * \return void
 */
void ldns_pkt_print(FILE *output, ldns_pkt *pkt);

/**
 * Converts a rr_list to presentation format and appends it to
 * the output buffer
 * \param[in] output the buffer to append output to
 * \param[in] list the ldns_rr_list to print
 * \return ldns_status
 */
ldns_status ldns_rr_list2buffer_str(ldns_buffer *output, ldns_rr_list *list);

/**
 * Converts the header of a packet to presentation format and appends it to
 * the output buffer
 * \param[in] output the buffer to append output to
 * \param[in] pkt the packet to convert the header of
 * \return ldns_status
 */
ldns_status ldns_pktheader2buffer_str(ldns_buffer *output, ldns_pkt *pkt);

void ldns_rr_list_print(FILE *, ldns_rr_list *);

void ldns_resolver_print(FILE *, ldns_resolver *);

#endif
