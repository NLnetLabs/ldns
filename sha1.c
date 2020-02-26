/*
 * modified for ldns by Jelte Jansen, original taken from OpenBSD:
 *
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 *
 * Test Vectors (from FIPS PUB 180-1)
 * "abc"
 *   A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
 * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *   84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
 * A million repetitions of "a"
 *   34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

/*
 * updated by Jeffrey Walton <noloader@gmail.com>, FEB 2020
 *   added x86 SHA-1 acceleration when available
 *   copyright assigned to LDNS project
 */

/* #define LITTLE_ENDIAN * This should be #define'd already, if true. */

#include <ldns/config.h>
#include <ldns/cpuinfo.h>
#include <ldns/sha1.h>
#include <string.h>  /* memcpy, memset, bcopy, bzero */
#include <stddef.h>  /* size_t and NULL */

#if defined(LDNS_X86_SHA_AVAILABLE)
# include <smmintrin.h>  /* _mm_extract_epi32 */
# include <tmmintrin.h>  /* _mm_shuffle_epi8 */
# include <emmintrin.h>  /* _mm_shuffle_epi32 */
# include <immintrin.h>  /* _mm_sha1msg1_epu32 and friends */
# define M128_CAST(x) ((__m128i *)(void *)(x))
# define CONST_M128_CAST(x) ((const __m128i *)(const void *)(x))
#endif  /* LDNS_X86_SHA_AVAILABLE */

#define SHA1HANDSOFF 1 /* Copies data before messing with it. */
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

typedef union {
    unsigned char c[64];
    unsigned int  l[16];
} CHAR64LONG16;

typedef void (*SHA1_TRANSFORM_FN)(uint32_t state[5], const unsigned char buffer[LDNS_SHA1_BLOCK_LENGTH]);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void
ldns_sha1_transform(uint32_t state[5], const unsigned char buffer[LDNS_SHA1_BLOCK_LENGTH])
{
    uint32_t a, b, c, d, e;
    CHAR64LONG16* block;

#ifdef SHA1HANDSOFF
    unsigned char workspace[LDNS_SHA1_BLOCK_LENGTH];
    block = (CHAR64LONG16 *)workspace;
    memcpy(block, buffer, LDNS_SHA1_BLOCK_LENGTH);
#else
    block = (CHAR64LONG16 *)buffer;
#endif

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}


#if defined(LDNS_X86_SHA_AVAILABLE)
# if defined(__GNUC__)
__attribute__ ((target ("sse4.2,sha")))
void
ldns_sha1_transform_x86(uint32_t state[5], const unsigned char buffer[LDNS_SHA1_BLOCK_LENGTH])
# else
void
ldns_sha1_transform_x86(uint32_t state[5], const unsigned char buffer[LDNS_SHA1_BLOCK_LENGTH])
# endif
{
    __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
    __m128i MASK, MSG0, MSG1, MSG2, MSG3;

    /* No need for SHA1HANDSOFF. _mm_loadu_si128 is an   */
    /* unaligned load and it will not segfault on a byte */
    /* aligned buffer. Ditto for _mm_storeu_si128.       */

    /* Shuffle mask */
    MASK = _mm_set_epi8(0,1,2,3, 4,5,6,7, 8,9,10,11, 12,13,14,15);

    /* Load initial values */
    ABCD = _mm_loadu_si128(CONST_M128_CAST(state));
    E0 = _mm_set_epi32(state[4], 0, 0, 0);
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

    /* Save current hash */
    ABCD_SAVE = ABCD;
    E0_SAVE = E0;

    /* Rounds 0-3 */
    MSG0 = _mm_loadu_si128(CONST_M128_CAST(buffer+0));
    MSG0 = _mm_shuffle_epi8(MSG0, MASK);
    E0 = _mm_add_epi32(E0, MSG0);
    E1 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

    /* Rounds 4-7 */
    MSG1 = _mm_loadu_si128(CONST_M128_CAST(buffer+16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_loadu_si128(CONST_M128_CAST(buffer+32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_loadu_si128(CONST_M128_CAST(buffer+48));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 16-19 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 20-23 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 24-27 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 28-31 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 32-35 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 36-39 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 40-43 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 44-47 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 48-51 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 52-55 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 56-59 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 60-63 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 64-67 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 68-71 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 72-75 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

    /* Rounds 76-79 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

    /* Add values back to state */
    E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

    /* Save state */
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
    _mm_storeu_si128(M128_CAST(state), ABCD);
    state[4] = _mm_extract_epi32(E0, 3);
}
#endif  /* LDNS_X86_SHA_AVAILABLE */


/* SHA1Init - Initialize new context */

void
ldns_sha1_init(ldns_sha1_ctx *context)
{
    /* SHA1 initialization constants */
    context->count = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
}


/* Function pointer to a SHA implementation */

SHA1_TRANSFORM_FN get_sha1_transform_fn(void)
{
    /* Potential race in the double check'd init below. The */
    /* worst case is two threads each set function pointer. */
    static SHA1_TRANSFORM_FN sha1_transform_fn = NULL;

    if (sha1_transform_fn == NULL)
    {
        /* Default C transform */
        SHA1_TRANSFORM_FN tfn = &ldns_sha1_transform;

#if defined(LDNS_X86_SHA_AVAILABLE)
        if (ldns_cpu_x86_sha1())
        {
            tfn = &ldns_sha1_transform_x86;
        }
#endif

        if (sha1_transform_fn == NULL) {
            sha1_transform_fn = tfn;
        }
    }

    return sha1_transform_fn;
}


/* Run your data through this. */

void
ldns_sha1_update(ldns_sha1_ctx *context, const unsigned char *data, unsigned int len)
{
    unsigned int i;
    unsigned int j;
    SHA1_TRANSFORM_FN sha1_transform_fn;

    sha1_transform_fn = get_sha1_transform_fn();
    j = (unsigned int)((context->count >> 3) & 63);
    context->count += (len << 3);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        sha1_transform_fn(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            sha1_transform_fn(context->state, &data[i]);
        }
        j = 0;
    }
    else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void
ldns_sha1_final(unsigned char digest[LDNS_SHA1_DIGEST_LENGTH], ldns_sha1_ctx *context)
{
    unsigned int i;
    unsigned char finalcount[8];
    unsigned long long pad[3];
    SHA1_TRANSFORM_FN sha1_transform_fn;

    sha1_transform_fn = get_sha1_transform_fn();
    pad[0] = pad[1] = pad[2] = 0;  /* 24 bytes of 0 */

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count >>
            ((7 - (i & 7)) * 8)) & 255);  /* Endian independent */
    }
    ldns_sha1_update(context, (unsigned char *)"\200", 1);
    while ((context->count & 504) < 448 - 24*8) {  /* bits */
        ldns_sha1_update(context, (unsigned char *)pad, 24);
    }
    while ((context->count & 504) < 448 -  8*8) {  /* bits */
        ldns_sha1_update(context, (unsigned char *)pad, 8);
    }
    while ((context->count & 504) != 448) {  /* bits */
        ldns_sha1_update(context, (unsigned char *)pad, 1);
    }
    ldns_sha1_update(context, finalcount, 8);  /* Should cause a SHA1Transform() */

    if (digest != NULL)
        for (i = 0; i < LDNS_SHA1_DIGEST_LENGTH; i++) {
            digest[i] = (unsigned char)((context->state[i >> 2] >>
                ((3 - (i & 3)) * 8)) & 255);
      }
#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite its own static vars */
    sha1_transform_fn(context->state, context->buffer);
#endif
}

unsigned char *
ldns_sha1(const unsigned char *data, unsigned int data_len, unsigned char *digest)
{
    ldns_sha1_ctx ctx;
    ldns_sha1_init(&ctx);
    ldns_sha1_update(&ctx, data, data_len);
    ldns_sha1_final(digest, &ctx);
    return digest;
}
