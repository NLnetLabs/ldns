/*
 * dane.h -- defines for the DNS-Based Authentication of Named Entities (DANE)
 *                           Transport Layer Security (TLS) Protocol: TLSA
 *
 * Copyright (c) 2012, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

/**
 * \file dane.h
 *
 * This module contains base functions for creating and verifying TLSA RR's
 * with PKIX certificates, certificate chains and validation stores.
 * (See RFC6394 and RFC6698).
 * 
 * Since those functions heavily rely op cryptographic operations,
 * this module is dependent on openssl.
 * 
 */
 

#ifndef LDNS_DANE_H
#define LDNS_DANE_H

#include <ldns/common.h>
#include <ldns/rdata.h>
#include <ldns/rr.h>
#if LDNS_BUILD_CONFIG_HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* LDNS_BUILD_CONFIG_HAVE_SSL */

#ifdef __cplusplus
extern "C" {
#endif

enum ldns_enum_tlsa_certificate_usage
{
	LDNS_TLSA_USAGE_CA_CONSTRAINT			= 0,
	LDNS_TLSA_USAGE_SERVICE_CERTIFICATE_CONSTRAINT	= 1,
	LDNS_TLSA_USAGE_TRUST_ANCHOR_ASSERTION		= 2,
	LDNS_TLSA_USAGE_DOMAIN_ISSUED_CERTIFICATE	= 3
};
typedef enum ldns_enum_tlsa_certificate_usage ldns_tlsa_certificate_usage;

enum ldns_enum_tlsa_selector
{
	LDNS_TLSA_SELECTOR_FULL_CERTIFICATE	= 0,
	LDNS_TLSA_SELECTOR_SUBJECTPUBLICKEYINFO	= 1
};
typedef enum ldns_enum_tlsa_selector ldns_tlsa_selector;

enum ldns_enum_tlsa_matching_type
{
	LDNS_TLSA_MATCHING_TYPE_NO_HASH_USED	= 0,
	LDNS_TLSA_MATCHING_TYPE_SHA256		= 1,
	LDNS_TLSA_MATCHING_TYPE_SHA512		= 2
};
typedef enum ldns_enum_tlsa_matching_type ldns_tlsa_matching_type;

enum ldns_enum_dane_protocol
{
	LDNS_DANE_PROTOCOL_UNSPEC = 0,
	LDNS_DANE_PROTOCOL_IPV4   = 1,
	LDNS_DANE_PROTOCOL_IPV6   = 2,
	LDNS_DANE_PROTOCOL_IP     = 3
};
typedef enum ldns_enum_dane_protocol ldns_dane_protocol;

enum ldns_enum_dane_transport
{
	LDNS_DANE_TRANSPORT_TCP  = 0,
	LDNS_DANE_TRANSPORT_UDP  = 1,
	LDNS_DANE_TRANSPORT_SCTP = 2
};
typedef enum ldns_enum_dane_transport ldns_dane_transport;


/**
 * Creates a dname consisting of the given name, prefixed by the service
 * port and protocol name of the transport:
 * _<port>._<protocol>.<name>
 * TODO: How to choose protocol SCTP?
 *
 * \param[out] tlsa_owner The created dname.
 * \param[in] name The dname that should be prefixed by the service and
 *                 protocol.
 * \param[in] port The service port number.
 * \param[in] transport The transport for wich the name should be created.
 * \return LDNS_STATUS_OK on success or an error code otherwise.
 */
ldns_status ldns_dane_create_tlsa_owner(ldns_rdf** tlsa_owner,
		const ldns_rdf* name, int port, ldns_dane_transport transport);


#if LDNS_BUILD_CONFIG_HAVE_SSL
/**
 * Creates a LDNS_RDF_TYPE_HEX type rdf bases on the binary data choosen by
 * the selector and encoded using matching_type.
 *
 * \param[out] rdf The created created rdf of type LDNS_RDF_TYPE_HEX.
 * \param[in] cert The certificate from which the data is selected
 * \param[in] selector The full certificate or the public key
 * \param[in] matching_type The full data or the SHA256 or SHA512 hash
 *                          of the selected data
 * \return LDNS_STATUS_OK on success or an error code otherwise.
 */
ldns_status ldns_dane_cert2rdf(ldns_rdf** rdf, X509* cert,
		ldns_tlsa_selector      selector,
		ldns_tlsa_matching_type matching_type);


/**
 * Selects the certificate from cert, extra_certs or the pkix_validation_store
 * based on the value of cert_usage and index.
 *
 * \param[out] selected_cert The selected cert.
 * \param[in] cert The certificate to validate (or not)
 * \param[in] extra_certs Intermediate certificates that might be necessary
 *            during validation. May be NULL, except when the certificate 
 *            usage is "Trust Anchor Assertion" because the trust anchor has
 *            to be provided.(otherwise choose a "Domain issued certificate!"
 * \param[in] pkix_validation_store Used when the certificate usage is 
 *            "CA constraint" or "Service Certificate Constraint" to 
 *            validate the certificate and, in case of "CA constraint",
 *            select the CA.
 *            When NULL, validation is explicitely turned off and the
 *            behaviour is then the same as for "Trust anchor assertion"
 *            and "Domain issued certificate" respectively.
 * \param[in] cert_usage Which certificate to use and how to validate.
 * \param[in] index Used to select the trust anchor when certificate usage
 *            is "Trust Anchor Assertion". 1 is the last certificate in the
 *            validation chain. 2 the one but last, etc. When index is 0,
 *            the last certificate is used that MUST be self-signed.
 *            This can help to make sure that the intended (self signed)
 *            trust anchor is actually present in extra_certs (which is a
 *            DANE requirement).
 * \return LDNS_STATUS_OK on success or an error code otherwise.
 */
ldns_status ldns_dane_select_certificate(X509** selected_cert,
		X509* cert, STACK_OF(X509)* extra_certs,
		X509_STORE* pkix_validation_store,
		ldns_tlsa_certificate_usage cert_usage, int index);

/**
 * Creates a TLSA resource record from the certificate.
 * No PKIX validation is performed! The given certificate is used as data
 * regardless the value of certificate_usage.
 *
 * \param[out] tlsa The created TLSA resource record.
 * \param[in] certificate_usage The value for the Certificate Usage field
 * \param[in] selector The value for the Selector field
 * \param[in] matching_type The value for the Matching Type field
 * \param[in] cert The certificate which data will be represented
 *
 * \return LDNS_STATUS_OK on success or an error code otherwise.
 */
ldns_status
ldns_dane_create_tlsa_rr(ldns_rr** tlsa,
		ldns_tlsa_certificate_usage certificate_usage,
		ldns_tlsa_selector          selector,
		ldns_tlsa_matching_type     matching_type,
		X509* cert);

ldns_status
ldns_dane_verify_rr(const ldns_rr* tlsa_rr,
		X509* cert, STACK_OF(X509)* extra_certs,
		X509_STORE* pkix_validation_store);

ldns_status
ldns_dane_verify(ldns_rr_list* tlsas,
		X509* cert, STACK_OF(X509)* extra_certs,
		X509_STORE* pkix_validation_store);
#endif /* LDNS_BUILD_CONFIG_HAVE_SSL */

#ifdef __cplusplus
}
#endif

#endif /* LDNS_DANE_H */

