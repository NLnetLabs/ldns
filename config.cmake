/* config.cmake - Used by CMake to generate final configuration header */

#ifndef LDNS_CONFIG_H
#define LDNS_CONFIG_H

#cmakedefine HAVE_ARPA_INET_H
#cmakedefine HAVE_B64_NTOP
#cmakedefine HAVE_B64_PTON
#cmakedefine HAVE_BASETSD_H
#cmakedefine HAVE_ECDSA_SIG_GET0
#cmakedefine HAVE_ENDPROTOENT
#cmakedefine HAVE_ENDSERVENT
#cmakedefine HAVE_EVP_MD_CTX_NEW
#cmakedefine HAVE_EVP_PKEY_BASE_ID
#cmakedefine HAVE_EVP_PKEY_KEYGEN
#cmakedefine HAVE_EVP_SHA256
#cmakedefine HAVE_EVP_SHA384
#cmakedefine HAVE_EVP_SHA512
#cmakedefine HAVE_FCNTL
#cmakedefine HAVE_GETADDRINFO
#cmakedefine HAVE_GMTIME_R
#cmakedefine HAVE_INET_ATON
#cmakedefine HAVE_INET_NTOP
#cmakedefine HAVE_INET_PTON
#cmakedefine HAVE_ISASCII
#cmakedefine HAVE_ISBLANK
#cmakedefine HAVE_LOCALTIME_R
#cmakedefine HAVE_MEMMOVE
#cmakedefine HAVE_NETDB_H
#cmakedefine HAVE_NETINET_IN_H
#cmakedefine HAVE_POLL
#cmakedefine HAVE_RANDOM
#cmakedefine HAVE_SLEEP
#cmakedefine HAVE_SNPRINTF
#cmakedefine HAVE_SSL
#cmakedefine HAVE_STDBOOL_H
#cmakedefine HAVE_STDINT_H
#cmakedefine HAVE_STRINGS_H
#cmakedefine HAVE_STRLCPY
#cmakedefine HAVE_STRTOUL
#cmakedefine HAVE_SYS_PARAM_H
#cmakedefine HAVE_SYS_SOCKET_H
#cmakedefine HAVE_TIMEGM
#cmakedefine HAVE_TIME_H
#cmakedefine HAVE_UNISTD_H
#cmakedefine HAVE_WINDOWS_H
#cmakedefine HAVE_WINSOCK2_H
#cmakedefine HAVE_WS2TCPIP_H

#cmakedefine RRTYPE_AVC
#cmakedefine RRTYPE_NINFO
#cmakedefine RRTYPE_OPENPGPKEY
#cmakedefine RRTYPE_RKEY
#cmakedefine RRTYPE_TA
#cmakedefine STDC_HEADERS @stdc_header_bool@
#cmakedefine STDERR_MSGS
#cmakedefine USE_DANE
#cmakedefine USE_DANE_VERIFY
#cmakedefine USE_DSA
#cmakedefine USE_ECDSA
#cmakedefine USE_ED25519
#cmakedefine USE_ED448
#cmakedefine USE_GOST
#cmakedefine USE_SHA2
#cmakedefine USE_WINSOCK
#cmakedefine WORDS_BIGENDIAN

#cmakedefine in_port_t uint16_t
#cmakedefine in_addr_t @in_addr_t@
