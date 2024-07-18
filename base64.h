#ifndef _BASE64_H_
#define _BASE64_H_

// Byte value that represents an invalid base64 character.
#define __B64_INVALID (0xff)

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

/*
 * Returns the exact length an encoded string will be, given the
 * decoded data is n bytes.
 */
size_t static inline
base64_encoded_size(size_t n)
{
	return (((int) (n/3.0) + ((n/3.0) > (int) (n/3.0))) * 4);
}

/*
 * Returns the maximum length the decoded data may be, given the
 * encoded string is n bytes.
 */
size_t static inline
base64_decoded_size(size_t n)
{
	return (((int) (n/4.0) + ((n/4.0) > (int) (n/4.0))) * 3);
}

/*
 * Encode the data from _src which is n bytes long.
 *
 * Warning: This function assumes _dst is large enough to hold the
 * encoded data. See base64_encoded_size().
 */
void static
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
 * Decodes a data into _dst from an base64 encoded string in _src.
 *
 * Warning: This function assumes _dst is large enough to hold the
 * decoded data. See base64_decoded_size().
 */
size_t static
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
	return (3 * (n / 4)) - (src[n - 1] == '=') - (src[n - 2] == '=');
}


/*
 * Checks if a string is a valid base64 encoding.
 * Returns 0 when valid and -1 whe invalid.
 */
int static
base64_valid(const char* s, size_t n)
{
	if (n % 4 != 0)
		return -1;
	while (n)
		if (__base64_decode(s[--n]) == __B64_INVALID)
			return -1;
	return 0;
}

#endif // _BASE64_H_
