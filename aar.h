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


/*
  An aar archive is made from concatenated encrypted aar files. An
  encrypted aar file has the following structure:
  
  Block    /--- 16 Bytes ---\
           +----------------+ <- Record data
           |                |
         //////////////////////
           |        ........|
           +----------------+ <- Record description
           |                |
         //////////////////////
           |     ...........|
           +----------------+ <- Record header
           |$$$$$$$$$$$$$$$$|
           |DDDDDDDDdddddddd|
           |############....|
           +----------------+ <- EOF


    Key | Meaning
    ----+--------------------
    $   | Nonce byte.
    #   | Checksum byte.
    .   | Padding
*/


#ifndef _AAR_H_
#define _AAR_H_

#define AAR_DESC_MAX        1024      // Maximum length of a file path
#define AAR_KEY_SIZE        Bytes(32) // Byte size of the AES key
#define AAR_BASE64_KEY_SIZE Bytes(44) // Size of a base64 encode AES key
#define AAR_BLOCK_SIZE      Bytes(16)

typedef u32 aar_checksum;
#define AAR_CHECKSUM_SIZE   sizeof(aar_checksum)
#define AAR_CHECKSUM_INIT   0

#define sizeof_member(type, member) (sizeof(((type){0}).member))


typedef struct {
	byte data[AAR_KEY_SIZE];
} aar_key;
TYPEDEF_OK(aar_key);

// Number of encryption passes
#define AAR_CRYPT_PASSES 1

// AAR File Format
typedef struct {
	u8           nonce[AAR_BLOCK_SIZE];
	u64          data_length;           // Byte length of plaintext data
	u64          desc_length;           // Byte length of desc data. Must be <= AAR_MAX_PATH
	aar_checksum chk_hdr;               // Checksum of nonce, data_length, and desc_length
	aar_checksum chk_desc;              // Checksum of plaintext desc
	aar_checksum chk_data;              // Checksum of plaintext data
	u8           desc[AAR_DESC_MAX];    // Description of data (also used as the file path/name)
} aar_hdr;
TYPEDEF_OK(aar_hdr);

// Byte length aligned to AAR_BLOCK_SIZE
#define AAR_PADDING(nbytes)						\
	((nbytes)							\
		+ ((nbytes) % AAR_BLOCK_SIZE > 0)			\
		* (AAR_BLOCK_SIZE - ((nbytes) % AAR_BLOCK_SIZE)))
#define AAR_BLOCKS(nbytes)  (AAR_PADDING(nbytes) / AAR_BLOCK_SIZE)

// The absolute minimum byte length a record header could possibly be on disk.
#define AAR_HDR_MIN							\
	AAR_PADDING(sizeof_member(aar_hdr, nonce)			\
		+ sizeof_member(aar_hdr, data_length)			\
		+ sizeof_member(aar_hdr, desc_length)			\
		+ sizeof_member(aar_hdr, chk_hdr)			\
		+ sizeof_member(aar_hdr, chk_data)			\
		+ sizeof_member(aar_hdr, chk_desc))

// The absolute maxiumum byte length a record header could possibly be.
#define AAR_HDR_MAX (AAR_HDR_MIN + AAR_PADDING(sizeof_member(aar_hdr, desc)))

// The full byte length of a record's header that is written to disk.
#define AAR_HDR_BYTES(hdr)						\
	(AAR_PADDING(AAR_HDR_MIN)					\
		+ (((hdr).desc_length > 0)				\
			? AAR_PADDING((hdr).desc_length)		\
			: 0))

// The full block length of a record's header that is written to disk.
#define AAR_HDR_BLOCKS(hdr) (AAR_HDR_BYTES(hdr) / AAR_BLOCK_SIZE)

// The full byte length of a record's data that's written to disk.
#define AAR_DATA_BYTES(hdr) (AAR_PADDING((hdr).data_length))

// The entire record's byte length.
#define AAR_REC_BYTES(hdr)  (AAR_HDR_BYTES(hdr) + AAR_DATA_BYTES(hdr))

#endif // _AAR_H_
