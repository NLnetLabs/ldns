cmake_minimum_required(VERSION 3.2)
project(ldns)

include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(FindOpenSSL)
include(TestBigEndian)

set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "${OPENSSL_LIBRARIES}")
set(CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h")

check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_symbol_exists(b64_ntop resolv.h HAVE_B64_NTOP)
check_symbol_exists(b64_pton resolv.h HAVE_B64_PTON)
check_symbol_exists(ECDSA_SIG_get0 openssl/ecdsa.h HAVE_ECDSA_SIG_GET0)
check_symbol_exists(endprotoent netdb.h HAVE_ENDPROTOENT)
check_symbol_exists(endservent netdb.h HAVE_ENDSERVENT)
check_symbol_exists(EVP_MD_CTX_new openssl/evp.h HAVE_EVP_MD_CTX_NEW)
check_symbol_exists(EVP_PKEY_base_id openssl/evp.h HAVE_EVP_PKEY_BASE_ID)
check_symbol_exists(EVP_PKEY_keygen openssl/evp.h HAVE_EVP_PKEY_KEYGEN)
check_symbol_exists(EVP_sha256 "openssl/evp.h" HAVE_EVP_SHA256)
check_symbol_exists(EVP_sha384 openssl/evp.h HAVE_EVP_SHA384)
check_symbol_exists(EVP_sha512 openssl/evp.h HAVE_EVP_SHA512)
check_symbol_exists(fcntl unistd.h;fcntl.h HAVE_FCNTL)
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(netdb.h HAVE_NETDB_H)
check_include_file(netinet/in.h HAVE_NETINET_IN_H)
check_symbol_exists(in_addr_t arpa.inet.h HAVE_IN_ADDR_T)
check_symbol_exists(in_port_t netinet/in.h HAVE_IN_PORT_T)
check_symbol_exists(poll poll.h HAVE_POLL)
check_symbol_exists(random stdlib.h HAVE_RANDOM)
check_symbol_exists(sleep unistd.h HAVE_SLEEP)
check_symbol_exists(timegm time.h HAVE_TIMEGM)
check_symbol_exists(gmtime_r time.h HAVE_GMTIME_R)
check_symbol_exists(localtime_r time.h HAVE_LOCALTIME_R)
check_symbol_exists(isblank ctype.h HAVE_ISBLANK)
check_symbol_exists(isascii ctype.h HAVE_ISASCII)
check_symbol_exists(snprintf stdio.h HAVE_SNPRINTF)
check_symbol_exists(inet_pton arpa/inet.h HAVE_INET_PTON)
check_symbol_exists(inet_ntop arpa/inet.h HAVE_INET_NTOP)
check_symbol_exists(inet_aton arpa/inet.h HAVE_INET_ATON)
check_symbol_exists(memmove string.h HAVE_MEMMOVE)
check_include_file(stdbool.h HAVE_STDBOOL_H)
check_symbol_exists(strlcpy string.h HAVE_STRLCPY)
check_symbol_exists(strtoul stdlib.h HAVE_STRTOUL)
check_symbol_exists(getaddrinfo "sys/types.h;sys/socket.h;netdb.h" HAVE_GETADDRINFO)
if(NOT HAVE_GETADDRINFO)
	set(CMAKE_REQUIRED_LIBRARIES "ws2_32")
    check_symbol_exists(getaddrinfo "winsock2.h;ws2tcpip.h" HAVE_GETADDRINFO_WIN)
	if(HAVE_GETADDRINFO_WIN)
		set(HAVE_GETADDRINFO ON)
	endif()
endif()
if(NOT HAVE_IN_ADDR_T)
	set(in_addr_t "uint32_t")
endif()
check_type_size(socklen_t SOCKLEN_T)
if(NOT HAVE_SOCKLEN_T)
    set(CMAKE_EXTRA_INCLUDE_FILES "ws2tcpip.h")
    check_type_size(socklen_t SOCKLEN_T)
endif()
check_type_size(ssize_t HAVE_SSIZE_T)
if(NOT HAVE_SSIZE_T)
	set(CMAKE_EXTRA_INCLUDE_FILES "BaseTsd.h")
	check_type_size(SSIZE_T HAVE_BASETSD_H)
endif()
if (NOT HAVE_IN_PORT_T)
	set(in_port_t ON)
endif()
set(HAVE_SSL ${OPENSSL_FOUND})
check_include_file(time.h HAVE_TIME_H)
check_include_files("stdlib.h;stddef.h" HAVE_STDC_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(sys/param.h HAVE_SYS_PARAM_H)
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(windows.h HAVE_WINDOWS_H)
check_include_file(winsock2.h HAVE_WINSOCK2_H)
check_include_file(ws2tcpip.h HAVE_WS2TCPIP_H)
check_include_file(unistd.h HAVE_UNISTD_H)

if (NOT HAVE_STRINGS_H)
	check_include_file(string.h HAVE_STRING_H)
	if(HAVE_STRING_H)
		file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/strings.h "#include <string.h>")
		install(FILES ${CMAKE_CURRENT_BINARY_DIR}/strings.h DESTINATION include)
	endif()
endif()

if (NOT HAVE_SYS_TIME_H AND HAVE_TIME_H)
	file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/sys)
	file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/sys/time.h "#include <time.h>")
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sys/time.h DESTINATION include/sys)
endif()

if (NOT HAVE_UNISTD_H)
	file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/unistd.h "")
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/unistd.h DESTINATION include)
endif()

check_c_source_compiles("#include <stdio.h>
  void f (char *format, ...) __attribute__ ((format (printf, 1, 2)));
  void (*pf) (char *format, ...) __attribute__ ((format (printf, 1, 2)));
int main(void) { return 0; }"
HAVE_ATTR_FORMAT)
check_c_source_compiles("#include <stdio.h>
  void f (char *u __attribute__((unused)));
int main (void) { return 0; }"
HAVE_ATTR_UNUSED)

test_big_endian(WORDS_BIGENDIAN)

option(RRTYPE_AVC "Enables RR type AVC." OFF)
option(RRTYPE_NINFO "Enables RR type NINFO" OFF)
option(RRTYPE_OPENPGPKEY "Enables RR type OPENPGPKEY" OFF)
option(RRTYPE_RKEY "Enables RR type RKEY" OFF)
option(RRTYPE_TA "Enables RR type TA" OFF)
option(STDERR_MSGS "Enables printing messages to stderr" ON)
option(USE_DANE "enable DANE support" ON)
option(USE_DANE_VERIFY "enable DANE verify support" ON)
option(USE_DSA "enable DSA support" ON)
option(USE_ECDSA "enable ECDSA support" ON)
option(USE_ED25519 "enable ED25519 support" ON)
option(USE_ED448 "enable ED448 support" ON)
option(USE_GOST "enable GOST support" ON)
option(USE_SHA2 "enable SHA2 suite support" ON)

if(HAVE_WINDOWS_H)
    set(USE_WINSOCK 1)
endif()
if(HAVE_STDC_H)
    set(stdc_header_bool 1)
else()
    set(stdc_header_bool 0)
endif()

if(USE_ECDSA)
    check_symbol_exists(NID_X9_62_prime256v1 "openssl/evp.h" CAN_USE_ECDSA)
    check_symbol_exists(NID_secp384r1 "openssl/evp.h" CAN_USE_ECDSA2)
    if(NOT (CAN_USE_ECDSA AND CAN_USE_ECDSA2))
        message(SEND_ERROR "OpenSSL does not support ECDSA curves: please upgrade OpenSSL or rerun CMake with -DUSE_ECDSA=OFF")
    endif()
endif()
if(USE_ED25519)
    check_symbol_exists(NID_X25519 "openssl/evp.h" CAN_USE_ED25519)
    if(NOT CAN_USE_ED25519)
        message(SEND_ERROR "OpenSSL does not support ED25519 curves: please upgrade OpenSSL or rerun CMake with -DUSE_ED25519=OFF")
    endif()
endif()
if(USE_ED448)
    check_symbol_exists(NID_X448 "openssl/evp.h" CAN_USE_ED448)
    if(NOT CAN_USE_ED448)
        message(SEND_ERROR "OpenSSL does not support ED448 curves: please upgrade OpenSSL or rerun CMake with -DUSE_ED448=OFF")
    endif()
endif()

if(${HAVE_ATTR_FORMAT})
    set(ldns_build_config_have_attr_format 1)
else()
    set(ldns_build_config_have_attr_format 0)
endif()
if(${HAVE_ATTR_UNUSED})
    set(ldns_build_config_have_attr_unused 1)
else()
    set(ldns_build_config_have_attr_unused 0)
endif()
if(${HAVE_SOCKLEN_T})
    set(ldns_build_config_have_socklen_t 1)
else()
    set(ldns_build_config_have_socklen_t 0)
endif()
if(${USE_DANE})
    set(ldns_build_config_use_dane 1)
else()
    set(ldns_build_config_use_dane 0)
endif()
if(${HAVE_B32_PTON})
    set(ldns_build_config_have_b32_pton 1)
else()
    set(ldns_build_config_have_b32_pton 0)
endif()
if(${HAVE_B32_NTOP})
    set(ldns_build_config_have_b32_ntop 1)
else()
    set(ldns_build_config_have_b32_ntop 0)
endif()
if(${HAVE_INTTYPES_H})
    set(include_inttypes_h "#include <inttypes.h>")
    set(ldns_build_config_have_inttypes_h 1)
else()
    set(ldns_build_config_have_inttypes_h 0)
endif()
if(${HAVE_SYS_SOCKET_H})
    set(include_sys_socket_h "#include <sys/socket.h>")
endif()
if(${HAVE_SYS_TYPES_H})
    set(include_systypes_h "#include <sys/types.h>")
endif()
if(${HAVE_UNISTD_H})
    set(include_unistd_h "#include <unistd.h>")
endif()
if(${HAVE_SSL})
    set(ldns_build_config_have_ssl 1)
else()
    set(ldns_build_config_have_ssl 0)
endif()

set(LDNS_VERSION_MAJOR "1")
set(LDNS_VERSION_MINOR "7")
set(LDNS_VERSION_MICRO "0")
set(LDNS_VERSION "${LDNS_VERSION_MAJOR}.${LDNS_VERSION_MINOR}.${LDNS_VERSION_MICRO}")

configure_file(config.cmake ldns/config.h)
configure_file(ldns/util.h.in ldns/util.h)
configure_file(ldns/common.h.in ldns/common.h)
configure_file(ldns/net.h.in ldns/net.h)

file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/ldns/config.h "
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <assert.h>

#if defined(HAVE_B64_PTON) || defined(HAVE_B64_NTOP)
#include <resolv.h>
#endif

#ifndef HAVE_STRINGS_H
#define strcasecmp stricmp
#define strncasecmp strnicmp
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#ifndef BYTE_ORDER
#ifdef WORDS_BIGENDIAN
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif /* WORDS_BIGENDIAN */
#endif /* BYTE_ORDER */

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#define FD_SET_T (u_int)
#define HAVE_INET_PTON
#define HAVE_INET_NTOP
#define inet_pton InetPton
#define inet_ntop InetNtop
#endif

#ifdef HAVE_BASETSD_H
#include <BaseTsd.h>
#define ssize_t SSIZE_T
#endif
")

file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/ldns/config.h "
#ifdef __cplusplus
extern \"C\" {
#endif

int ldns_b64_ntop(uint8_t const *src, size_t srclength,
		  char *target, size_t targsize);
/**
 * calculates the size needed to store the result of b64_ntop
 */
/*@unused@*/
static inline size_t ldns_b64_ntop_calculate_size(size_t srcsize)
{
	return ((((srcsize + 2) / 3) * 4) + 1);
}
int ldns_b64_pton(char const *src, uint8_t *target, size_t targsize);
/**
 * calculates the size needed to store the result of ldns_b64_pton
 */
/*@unused@*/
static inline size_t ldns_b64_pton_calculate_size(size_t srcsize)
{
	return (((((srcsize + 3) / 4) * 3)) + 1);
}

/**
 * Given in dnssec_zone.c, also used in dnssec_sign.c:w

 */
int ldns_dname_compare_v(const void *a, const void *b);

#ifndef HAVE_SLEEP
/* use windows sleep, in millisecs, instead */
#define sleep(x) Sleep((x)*1000)
#endif

#ifndef HAVE_RANDOM
#define srandom(x) srand(x)
#define random(x) rand(x)
#endif

#ifndef HAVE_TIMEGM
#include <time.h>
time_t timegm (struct tm *tm);
#endif /* !TIMEGM */
#ifndef HAVE_GMTIME_R
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif
#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r(const time_t *timep, struct tm *result);
#endif
#ifndef HAVE_ISBLANK
int isblank(int c);
#endif /* !HAVE_ISBLANK */
#ifndef HAVE_ISASCII
int isascii(int c);
#endif /* !HAVE_ISASCII */
#ifndef HAVE_SNPRINTF
#include <stdarg.h>
int snprintf (char *str, size_t count, const char *fmt, ...);
int vsnprintf (char *str, size_t count, const char *fmt, va_list arg);
#endif /* HAVE_SNPRINTF */
#ifndef HAVE_INET_PTON
int inet_pton(int af, const char* src, void* dst);
#endif /* HAVE_INET_PTON */
#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif
#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *addr);
#endif
#ifndef HAVE_MEMMOVE
void *memmove(void *dest, const void *src, size_t n);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifdef USE_WINSOCK
#define SOCK_INVALID INVALID_SOCKET
#define close_socket(_s) do { if (_s > SOCK_INVALID) {closesocket(_s); _s = SOCK_INVALID;} } while(0)
#else
#define SOCK_INVALID -1
#define close_socket(_s) do { if (_s > SOCK_INVALID) {close(_s); _s = SOCK_INVALID;} } while(0)
#endif

#ifdef __cplusplus
}
#endif
#ifndef HAVE_GETADDRINFO
#include \"compat/fake-rfc2553.h\"
#endif
#ifndef HAVE_STRTOUL
#define strtoul (unsigned long)strtol
#endif

#endif
")

if(NOT HAVE_B64_NTOP)
	list(APPEND COMPAT_SOURCES compat/b64_ntop.c)
endif()
if(NOT HAVE_B64_PTON)
	list(APPEND COMPAT_SOURCES compat/b64_pton.c)
endif()
if(HAVE_WINDOWS_H)
	list(APPEND COMPAT_SOURCES compat/gettimeofday.c)
endif()
if(NOT HAVE_STRLCPY)
	list(APPEND COMPAT_SOURCES compat/strlcpy.c)
endif()
if(NOT HAVE_LOCALTIME_R)
	list(APPEND COMPAT_SOURCES compat/localtime_r.c)
endif()

set(LDNS_SOURCES buffer.c dane.c dname.c dnssec.c dnssec_sign.c dnssec_verify.c dnssec_zone.c
duration.c error.c higher.c host2str.c host2wire.c keys.c net.c packet.c parse.c
radix.c rbtree.c rdata.c resolver.c rr.c rr_functions.c sha1.c sha2.c str2host.c
tsig.c update.c util.c wire2host.c zone.c ${COMPAT_SOURCES})
set(COMPAT_SOURCES compat/b64_ntop.c compat/b64_pton.c compat/calloc.c compat/ctime_r.c
    compat/fake-rfc2553.c compat/gmtime_r.c compat/inet_aton.c compat/inet_ntop.c compat/inet_pton.c
    compat/isascii.c compat/isblank.c compat/localtime_r.c compat/malloc.c compat/memmove.c
    compat/realloc.c compat/snprintf.c compat/strlcpy.c compat/timegm.c)

if(HAVE_WINDOWS_H)
	set(PLATFORM_LIBRARIES ws2_32)
else()
	set(PLATFORM_LIBRARIES resolv)
endif()

add_library(ldns SHARED ${LDNS_SOURCES})
add_library(ldns_static STATIC ${LDNS_SOURCES})
set_property(TARGET ldns ldns_static PROPERTY C_STANDARD 99)
target_include_directories(ldns PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_include_directories(ldns_static PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_compile_definitions(ldns PRIVATE HAVE_CONFIG_H=1 IS_CMAKE_BUILD=1)
target_compile_definitions(ldns_static PRIVATE HAVE_CONFIG_H=1 IS_CMAKE_BUILD=1)
target_link_libraries(ldns OpenSSL::SSL OpenSSL::Crypto ${PLATFORM_LIBRARIES})
target_link_libraries(ldns_static OpenSSL::SSL OpenSSL::Crypto ${PLATFORM_LIBRARIES})
install(TARGETS ldns ldns_static DESTINATION lib)
install(DIRECTORY ldns/ DESTINATION include/ldns FILES_MATCHING PATTERN "*.h")
install(DIRECTORY ${CMAKE_BINARY_DIR}/ldns/ DESTINATION include/ldns FILES_MATCHING PATTERN "*.h")
