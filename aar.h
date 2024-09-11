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

  TODO: Update this diagram.

    BLock    /--- 16 Bytes ---\
             +----------------+ <- AES key
    0        |                |
    1        |                |
             +----------------+ <- Record header
    2        |                |
    3        |        ........|
             +----------------+ <- Record description
    4        |                |
           //////////////////////
    Rn       |     ...........|
             +----------------+ <- Record data
    D0       |                |
    D1       |                |
           //////////////////////
    Dn       |       .........|
             +----------------+
*/

#ifndef _AAR_H_
#define _AAR_H_

#define AAR_DESC_MAX        1024      // Maximum length of a file path
#define AAR_KEY_SIZE        Bytes(32) // Byte size of the AES key
#define AAR_BASE64_KEY_SIZE Bytes(44) // Size of a base64 encode AES key
#define AAR_BLOCK_SIZE      Bytes(16)

typedef u32 aar_checksum;
#define AAR_CHECKSUM_SIZE   sizeof(aar_checksum)
#define AAR_CHECKSUM_INIT    -1

#define sizeof_member(type, member) (sizeof(((type){0}).member))


typedef struct {
	byte data[AAR_KEY_SIZE];
} aes_key;
TYPEDEF_OK(aes_key);

// Number of encryption passes
#define AAR_CRYPT_PASSES 1

// AAR File Format
typedef struct {
	u64 block_count;        // Quantity of data blocks
	u64 block_offset;       // Byte difference between encrypted blocks and decrypted data
	u64 desc_length;        // Byte length of desc data. Must be <= AAR_MAX_PATH
	u8  desc[AAR_DESC_MAX]; // File path/description
} aar_record_header;
TYPEDEF_OK(aar_record_header);

// The absolute minimum byte length a record header could possibly be on disk.
#define AAR_RECORD_MIN							\
	(sizeof_member(aar_record_header, block_count)			\
		+ sizeof_member(aar_record_header, block_offset)	\
		+ sizeof_member(aar_record_header, desc_length))

// The absolute maxiumum byte length a record header could possibly be.
#define AAR_RECORD_MAX (AAR_RECORD_MIN + sizeof_member(aar_record_header, desc))

// Byte length aligned to AAR_BLOCK_SIZE
#define AAR_PADDING(nbytes)						\
	((nbytes)							\
		+ ((nbytes) % AAR_BLOCK_SIZE > 0)			\
		* (AAR_BLOCK_SIZE - ((nbytes) % AAR_BLOCK_SIZE)))
#define AAR_BLOCKS(nbytes)  (AAR_PADDING(nbytes) / AAR_BLOCK_SIZE)

// The full byte length of a record's header that is written to disk.
#define AAR_HDR_BYTES(hdr)						\
	(AAR_PADDING(AAR_RECORD_MIN + AAR_CHECKSUM_SIZE)		\
		+ (((hdr).desc_length > 0)				\
			? AAR_PADDING((hdr).desc_length + AAR_CHECKSUM_SIZE) \
			: 0))

// The full block length of a record's header that is written to disk.
#define AAR_HDR_BLOCKS(hdr) (AAR_HDR_BYTES(hdr) / AAR_BLOCK_SIZE)

// The full byte length of a record's data that's written to disk.
#define AAR_DATA_BYTES(hdr) (((hdr).block_count * AAR_BLOCK_SIZE) + AAR_PADDING(AAR_CHECKSUM_SIZE))

// The entire record's byte length.
#define AAR_REC_BYTES(hdr)  (AAR_HDR_BYTES(hdr) + AAR_DATA_BYTES(hdr))

#define AAR_FILE_HEADER_SIZE AAR_KEY_SIZE

// TODO: Use a magic version block
// #define AAR_MAGIC_VERSION    $("AARv0000")                             // Defines the version of the archive file format
// #define AAR_FILE_HEADER_SIZE (AAR_MAGIC_VERSION.length + AAR_KEY_SIZE) // (sizeof(AAR_MAGIC_VERSION) + AAR_KEY_SIZE)

#endif // _AAR_H_
