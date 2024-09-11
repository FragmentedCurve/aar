#define BACK_TO_TABLES // Use pre-calculated tables for AES
#include "contrib/aes256/aes256.h"
#include "contrib/aes256/aes256.c"

void
EncryptBlocks(void* _dest, size nblocks, aes_key key)
{
#ifndef _AAR_DEBUG_NOCRYPT
	aes256_context_t ctx;
	byte* dest = _dest;
	aes256_init(&ctx, (aes256_key_t*) &key);
	for (size pass = 0; pass < AAR_CRYPT_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			aes256_encrypt_ecb(&ctx, ((aes256_blk_t*) dest) + i);
		}
	}
	aes256_done(&ctx);
#endif
}

void
DecryptBlocks(void* _dest, size nblocks, aes_key key)
{
#ifndef _AAR_DEBUG_NOCRYPT
	aes256_context_t ctx;
	byte* dest = _dest;
	aes256_init(&ctx, (aes256_key_t*) &key);
	for (size pass = 0; pass < AAR_CRYPT_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			aes256_decrypt_ecb(&ctx, ((aes256_blk_t*) dest) + i);
		}
	}
	aes256_done(&ctx);
#endif
}
