/*
 * a error2str function to make sense of all the
 * error codes we have laying ardoun
 *
 * a Net::DNS like library for C
 * LibDNS Team @ NLnet Labs
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/dns.h>
#include <ldns/error.h>

ldns_lookup_table ldns_error_str[] = {
	{ LDNS_STATUS_OK, "all o.k." },
	{ LDNS_STATUS_EMPTY_LABEL, "Empty label" },
        { LDNS_STATUS_LABEL_OVERFLOW, "Label length overflow" },
        { LDNS_STATUS_DOMAINNAME_OVERFLOW, "Domainname length overflow" },
        { LDNS_STATUS_DOMAINNAME_UNDERFLOW, "Domainname length underflow (zero length)" },
        { LDNS_STATUS_DDD_OVERFLOW, "\\DDD sequence overflow (>255)" },
        { LDNS_STATUS_PACKET_OVERFLOW, "Packet size overflow" },
        { LDNS_STATUS_INVALID_POINTER, "Invalid compression pointer" },
        { LDNS_STATUS_MEM_ERR, "General memory error" },
        { LDNS_STATUS_INTERNAL_ERR, "Internal error, this should not happen" },
        { LDNS_STATUS_ERR, "General error, this should be more specific" },
        { LDNS_STATUS_INVALID_INT, "Conversion error, integer expected" },
        { LDNS_STATUS_INVALID_IP4, "Conversion error, ip4 addr expected" },
        { LDNS_STATUS_INVALID_IP6, "Conversion error, ip6 addr expected" },
        { LDNS_STATUS_INVALID_STR, "Conversion error, string expected" },
        { LDNS_STATUS_INVALID_B64, "Conversion error, b64 encoding expected" },
        { LDNS_STATUS_INVALID_HEX, "Conversion error, hex encoding expected" },
        { LDNS_STATUS_INVALID_TIME, "Conversion error, time encoding expected" },
        { LDNS_STATUS_NETWORK_ERR, "Could not send or receive, because of network error" },
        { LDNS_STATUS_ADDRESS_ERR, "Could not start AXFR, because of address error" },
        { LDNS_STATUS_UNKNOWN_INET, "Uknown address family" },
        { LDNS_STATUS_NOT_IMPL, "This function is not implemented (yet), please notify the developers" },
        { LDNS_STATUS_CRYPTO_UNKNOWN_ALGO, "Uknown cryptographic algorithm" },
        { LDNS_STATUS_CRYPTO_ALGO_NOT_IMPL, "Cryptographic algorithm not implemented" },
        { LDNS_STATUS_CRYPTO_NO_RRSIG, "No DNSSEC signature(s)" },
        { LDNS_STATUS_CRYPTO_NO_DNSKEY, "No DNSSEC public key(s)" },
        { LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY, "No signatures found for trusted DNSSEC public key(s)" },
        { LDNS_STATUS_CRYPTO_NO_MATCHING_KEYTAG_DNSKEY, "No keys with the keytag from the RRSIG found" },
        { LDNS_STATUS_CRYPTO_VALIDATED, "validated?!? TODO" },
        { LDNS_STATUS_CRYPTO_BOGUS, "Bogus DNSSEC signature" },
        { LDNS_STATUS_CRYPTO_SIG_EXPIRED, "DNSSEC signature has expired" },
        { LDNS_STATUS_CRYPTO_SIG_NOT_INCEPTED, "DNSSEC signature not incepted yet" },
        { LDNS_STATUS_CRYPTO_EXPIRATION_BEFORE_INCEPTION, "DNSSEC signature has expiration date earlier than inception date" },
	{ 0, NULL }
};

const char *
ldns_get_errorstr_by_id(ldns_status err)
{
        ldns_lookup_table *lt;

        lt = ldns_lookup_by_id(ldns_error_str, err);

        if (lt) {
                return lt->name;
        }
        return NULL;
}
