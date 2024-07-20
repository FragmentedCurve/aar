/*
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

typedef FILE file;
typedef u64 aar_checksum;

#define AAR_DESC_MAX        1024      // Maximum length of a file path
#define AAR_KEY_SIZE        Bytes(32) // Byte size of the AES key
#define AAR_BASE64_KEY_SIZE Bytes(44) // Size of a base64 encode AES key
#define AAR_BLOCK_SIZE      Bytes(16)
#define AAR_CHECKSUM_SIZE   sizeof(checksum_t)

#define sizeof_member(type, member) (sizeof(((type){0}).member))


typedef struct {
	byte data[AAR_KEY_SIZE];
} aes_key;
TYPEDEF_OK(aes_key);

// Number of encryption passes
#define AAR_AES_PASSES 1

// AAR File Format
typedef struct {
	u64          block_count;        // Quantity of data blocks
	u64          block_offset;       // Byte difference between encrypted blocks and decrypted data
	u64          desc_length;        // Byte length of desc data. Must be <= AAR_MAX_PATH
	u8           desc[AAR_DESC_MAX]; // File path/description
} aar_record_header;
TYPEDEF_OK(aar_record_header);

#define AAR_PADDING(nbytes) (nbytes + (nbytes % AAR_BLOCK_SIZE > 0) * (AAR_BLOCK_SIZE - (nbytes % AAR_BLOCK_SIZE)))
#define AAR_BLOCKS(nbytes) (AAR_PADDING(nbytes) / AAR_BLOCK_SIZE)

// TODO: Make AAR_MAGIC_VERSION a block long versioning scheme.
//#define AAR_MAGIC_VERSION      "AARv0000"   // Defines the version of the archive file format
#define AAR_FILE_HEADER_SIZE   AAR_KEY_SIZE // (sizeof(AAR_MAGIC_VERSION) + AAR_KEY_SIZE)

#define AAR_RECORD_MIN							\
	(sizeof_member(aar_record_header, block_count)			\
		+ sizeof_member(aar_record_header, block_offset)	\
		+ sizeof_member(aar_record_header, desc_length))

#define AAR_RECORD_MAX (AAR_RECORD_MIN + sizeof_member(aar_record_header, desc))

#endif // _AAR_H_
