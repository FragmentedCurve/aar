// Ghetto hack to avoid function name conflicts
#define base64_encode ltc_base64_encode
#define base64_decode ltc_base64_decode

#include "tomcrypt.h"

#undef base64_encode
#undef base64_decode

void
EncryptBlocks(void* _dest, size nblocks, aes_key key)
{
#ifndef _AAR_DEBUG_NOCRYPT
	symmetric_key skey;
	ubyte buf[AAR_BLOCK_SIZE];
	ubyte* dest = _dest;

	bzero(buf, AAR_BLOCK_SIZE);
	(void) aes_setup((ubyte*) &key, AAR_KEY_SIZE, 0, &skey);
	for (size pass = 0; pass < AAR_CRYPT_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			ubyte* t = dest + (AAR_BLOCK_SIZE * i);
			(void) aes_ecb_encrypt(t, buf, &skey);
			memcpy(t, buf, AAR_BLOCK_SIZE);
		}
	}
	aes_done(&skey);
#endif
}

void
DecryptBlocks(void* _dest, size nblocks, aes_key key)
{
#ifndef _AAR_DEBUG_NOCRYPT
	symmetric_key skey;
	ubyte buf[AAR_BLOCK_SIZE];
	ubyte* dest = _dest;

	bzero(buf, AAR_BLOCK_SIZE);
	(void) aes_setup((ubyte*) &key, AAR_KEY_SIZE, 0, &skey);
	for (size pass = 0; pass < AAR_CRYPT_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			ubyte* t = dest + (AAR_BLOCK_SIZE * i);
			(void) aes_ecb_decrypt(t, buf, &skey);
			memcpy(t, buf, AAR_BLOCK_SIZE);
		}
	}
	aes_done(&skey);
#endif
}
