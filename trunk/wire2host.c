/*
 * wire2host.c
 *
 * conversion routines from the wire to the host
 * format.
 * This will usually just a re-ordering of the
 * data (as we store it in network format)
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

/**
 * transform a wireformatted rdata to our
 * internal representation. We need to the
 * length, and the type and put the data in
 */
ssize_t
rdata_buf_to_rdf(ldns_rdf *rd, ldns_buf *buffer)
{
	/* TODO TODO */
	switch(RDATA_TYPESS) {
		case RDF_TYPE_NONE:
			break;
		case RDF_TYPE_DNAME:
			/* can be compressed or not */
			break;
		case RDF_TYPE_INT8:
			break;
		case RDF_TYPE_INT16:
			break;
		case RDF_TYPE_INT32:
			break;
		case RDF_TYPE_INT48:
			break;
		case RDF_TYPE_A:     
			break;
		case RDF_TYPE_AAAA:
			break;
		case RDF_TYPE_STR:
			break;
		case RDF_TYPE_APL:
			break;
		case RDF_TYPE_B64:
			break;
		case RDF_TYPE_HEX:
			break;
		case RDF_TYPE_NSEC: 
			break;
		case RDF_TYPE_TYPE: 
			break;
		case RDF_TYPE_CLASS:
			break;
		case RDF_TYPE_CERT:
			break;
		case RDF_TYPE_ALG:
			break;
		case RDF_TYPE_UNKNOWN:
			break;
		case RDF_TYPE_TIME:
			break;
		case RDF_TYPE_SERVICE:
			break;
		case RDF_TYPE_LOC:
			break;
	}	

}

