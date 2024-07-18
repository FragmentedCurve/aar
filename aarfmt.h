/*
  
 */

#ifndef _AARFMT_H_
#define _AARFMT_H_

#include "typeok.h"

typedef FILE file;

#define AAR_PATH_MAX 1024

#define AAR_KEY_SIZE        Bytes(32) // Byte size of the AES key
#define AAR_BASE64_KEY_SIZE Bytes(44) // Size of a base64 encode AES key
#define AAR_BLOCK_SIZE      Bytes(16)

#define sizeof_member(type, member) (sizeof(((type){}).member))

typedef struct {
	byte data[AAR_KEY_SIZE];
} aes_key;
TYPEDEF_OK(aes_key);

// Number of encryption passes
#define AAR_AES_PASSES 1

// AAR File Format
typedef struct {
	u64 block_count;        // Quantity of AES blocks
	u64 block_offset;       // Byte difference between AES blocks and decrypted content
	u64 desc_size;          // Byte length of desc data. Must be <= AAR_MAX_PATH
	u8  desc[AAR_PATH_MAX]; // File path/description
} aar_record_header;
TYPEDEF_OK(aar_record_header);

#define AAR_PADDING(nbytes) (nbytes + (AAR_BLOCK_SIZE - (nbytes % AAR_BLOCK_SIZE)))
#define AAR_BLOCKS(nbytes) (AAR_PADDING(nbytes) / AAR_BLOCK_SIZE)

#define AAR_MAGIC_VERSION      "AARv0000"   // Defines the version of the archive file format
#define AAR_FILE_HEADER_SIZE   AAR_KEY_SIZE // (sizeof(AAR_MAGIC_VERSION) + AAR_KEY_SIZE)
#define AAR_RECORD_MIN							\
	(sizeof_member(aar_record_header, block_count)			\
		+ sizeof_member(aar_record_header, block_offset)	\
		+ sizeof_member(aar_record_header, desc_size))
#define AAR_RECORD_MAX (AAR_RECORD_MIN + sizeof_member(aar_record_header, desc))

#endif // _AARFMT_H_
