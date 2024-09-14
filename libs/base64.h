/*
 * Copyright (c) 2024 Paco Pascal <me@pacopascal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _BASE64_H_
#define _BASE64_H_

// Default to using a lookup table
#if    !defined _BASE64_TABLE  \
    && !defined _BASE64_SWITCH \
    && !defined _BASE64_IFELSE
#define _BASE64_TABLE
#endif

// Byte value that represents an invalid base64 character.
#define __B64_INVALID (0xff)

#ifdef _BASE64_TABLE
static const unsigned char __base64_encode_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
};

static const unsigned char __base64_decode_table[] = {
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  /* + */    62,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  /* / */    63,
	/* 0 */    52,  /* 1 */    53,  /* 2 */    54,  /* 3 */    55,
	/* 4 */    56,  /* 5 */    57,  /* 6 */    58,  /* 7 */    59,
	/* 8 */    60,  /* 9 */    61,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  /* = */     0,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  /* A */     0,  /* B */     1,  /* C */     2,
	/* D */     3,  /* E */     4,  /* F */     5,  /* G */     6,
	/* H */     7,  /* I */     8,  /* J */     9,  /* K */    10,
	/* L */    11,  /* M */    12,  /* N */    13,  /* O */    14,
	/* P */    15,  /* Q */    16,  /* R */    17,  /* S */    18,
	/* T */    19,  /* U */    20,  /* V */    21,  /* W */    22,
	/* X */    23,  /* Y */    24,  /* Z */    25,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
	__B64_INVALID,  /* a */    26,  /* b */    27,  /* c */    28,
	/* d */    29,  /* e */    30,  /* f */    31,  /* g */    32,
	/* h */    33,  /* i */    34,  /* j */    35,  /* k */    36,
	/* l */    37,  /* m */    38,  /* n */    39,  /* o */    40,
	/* p */    41,  /* q */    42,  /* r */    43,  /* s */    44,
	/* t */    45,  /* u */    46,  /* v */    47,  /* w */    48,
	/* x */    49,  /* y */    50,  /* z */    51,  __B64_INVALID,
	__B64_INVALID,  __B64_INVALID,  __B64_INVALID,  __B64_INVALID,
};

// 0x7f protects from going out-of-bounds.
#define __base64_decode(i) (__base64_decode_table[0x7f & (i)])
#define __base64_encode(i) (__base64_encode_table[(i)])
#endif // _BASE64_TABLE

#ifdef _BASE64_SWITCH
static unsigned char
__base64_encode(unsigned char x)
{
	switch (x) {
	case  0: case  1: case  2: case  3: case  4: case  5:
	case  6: case  7: case  8: case  9: case 10: case 11:
	case 12: case 13: case 14: case 15: case 16: case 17:
	case 18: case 19: case 20: case 21: case 22: case 23:
	case 24: case 25:
		return x + 'A';

	case 26: case 27: case 28: case 29: case 30: case 31:
	case 32: case 33: case 34: case 35: case 36: case 37:
	case 38: case 39: case 40: case 41: case 42: case 43:
	case 44: case 45: case 46: case 47: case 48: case 49:
	case 50: case 51:
		return (x - 26) + 'a';

	case 52: case 53: case 54: case 55: case 56:
	case 57: case 58: case 59: case 60: case 61:
		return (x - 52) + '0';

	case 62:
		return '+';
	case 63:
		return '/';

	default:
		return __B64_INVALID;
	}
}

static unsigned char
__base64_decode(unsigned char x)
{
	switch (x) {
	case 'A': case 'B': case 'C': case 'D': case 'E':
	case 'F': case 'G': case 'H': case 'I': case 'J':
	case 'K': case 'L': case 'M': case 'N': case 'O':
	case 'P': case 'Q': case 'R': case 'S': case 'T':
	case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
		return x - 'A';

	case 'a': case 'b': case 'c': case 'd': case 'e':
	case 'f': case 'g': case 'h': case 'i': case 'j':
	case 'k': case 'l': case 'm': case 'n': case 'o':
	case 'p': case 'q': case 'r': case 's': case 't':
	case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
		return (x + 26) - 'a';

	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return (x + 52) - '0';

	case '+':
		return 62;

	case '/':
		return 63;

	case '=':
		return 0;

	default:
		return __B64_INVALID;
	}
}
#endif // _BASE64_SWITCH

#ifdef _BASE64_IFELSE
static unsigned char
__base64_encode(unsigned char x)
{
	if (x >= 0 && x <= 25) {
		return x + 'A';
	} else if (x >= 26 && x <= 51) {
		return (x - 26) + 'a';
	} else if (x >= 52 && x <= 61) {
		return (x - 52) + '0';
	} else if (x == 62) {
		return '+';
	} else if (x == 63) {
		return '/';
	}
	return __B64_INVALID;
}

static unsigned char
__base64_decode(unsigned char x)
{
	if (x >= 'A' && x <= 'Z') {
		return x - 'A';
	} else if (x >= 'a' && x <= 'z') {
		return (x + 26) - 'a';
	} else if (x >= '0' && x <= '9') {
		return (x + 52) - '0';
	} else if (x == '+') {
		return 62;
	} else if (x == '/') {
		return 63;
	} else if (x == '=') {
		return 0;
	}
	return __B64_INVALID;
}
#endif // _BASE64_IFELSE

/*
  Returns the exact length an encoded string will be, given the
  decoded data is n bytes.
 */
static size_t
base64_encoded_size(size_t n)
{
	return (((int) (n/3.0) + ((n/3.0) > (int) (n/3.0))) * 4);
}

/*
  Returns the maximum length the decoded data may be, given the
  encoded string is n bytes.
 */
static size_t
base64_decoded_size(size_t n)
{
	return (((int) (n/4.0) + ((n/4.0) > (int) (n/4.0))) * 3);
}

/*
  Encode the data from _src which is n bytes long.

  Warning: This function assumes _dst is large enough to hold the
           encoded data. See base64_encoded_size().
 */
static void
base64_encode(void* _dst, const void* _src, size_t n)
{
	unsigned char* dst = (unsigned char*) _dst;
	const unsigned char* src = (const unsigned char*) _src;
	
	for (size_t i = 2; i < n; i += 3) {
		*dst     = __base64_encode(0x3f & (src[i - 2] >> 2));
		*(++dst) = __base64_encode(0x3f & ((src[i - 2] << 4) | (src[i - 1] >> 4)));
		*(++dst) = __base64_encode(0x3f & ((src[i - 1] << 2) | (src[i] >> 6)));
		*(++dst) = __base64_encode(0x3f & src[i]);
		++dst;
	}

	switch (n % 3) {
	case 1: {
		*dst     = __base64_encode(0x3f & (src[n - 1] >> 2));
		*(++dst) = __base64_encode(0x3f & (src[n - 1] << 4));
		*(++dst) = '=';
		*(++dst) = '=';
	} break;
	case 2: {
		*dst     = __base64_encode(0x3f & (src[n - 2] >> 2));
		*(++dst) = __base64_encode(0x3f & ((src[n - 2] << 4) | (src[n - 1] >> 4)));
		*(++dst) = __base64_encode(0x3f & (src[n - 1] << 2));
		*(++dst) = '=';
	} break;
	}
}

/*
  Decodes a data into _dst from an base64 encoded string in _src.

  Warning: This function assumes _dst is large enough to hold the
           decoded data. See base64_decoded_size().
 */
static size_t
base64_decode(void* _dst, const void* _src, size_t n)
{
	unsigned char* dst = (unsigned char*) _dst;
	const unsigned char* src = (const unsigned char*) _src;

	for (size_t i = 3; i < n; i += 4) {
		*dst     = (__base64_decode(src[i - 3]) << 2) | (__base64_decode(src[i - 2]) >> 4);
		*(++dst) = (__base64_decode(src[i - 2]) << 4) | (__base64_decode(src[i - 1]) >> 2);
		*(++dst) = (__base64_decode(src[i - 1]) << 6) | (__base64_decode(src[i]));
		++dst;
	}

	// Branchless checking for trailing '=' characters.
	return (3 * (n >> 2)) - (src[n - 1] == '=') - (src[n - 2] == '=');
}

/*
  Checks if a string is a valid base64 encoding.
  Returns 0 when valid and -1 whe invalid.
 */
static int
base64_valid(const char* s, size_t n)
{
	// n % 4 != 0
	if (n & 3) {
		return -1;
	}

	// The case 'xx=z' will be caught in the loop below.
	n -= (s[n - 1] == '=') + (s[n - 2] == '=');

	while (n) {
		if (__base64_decode(s[--n]) == __B64_INVALID || s[n] == '=') {
			return -1;
		}
	}

	return 0;
}

#endif // _BASE64_H_
