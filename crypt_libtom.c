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


void
EncryptBlocks(void* _dest, size nblocks, aes_key key)
{
#ifndef _AAR_DEBUG_NOCRYPT
	symmetric_key skey;
	ubyte* dest = _dest;
	(void) aes_setup((ubyte*) &key, AAR_KEY_SIZE, 0, &skey);
	for (size pass = 0; pass < AAR_CRYPT_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			ubyte* t = dest + (AAR_BLOCK_SIZE * i);
			(void) aes_ecb_encrypt(t, t, &skey);
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
	ubyte* dest = _dest;
	(void) aes_setup((ubyte*) &key, AAR_KEY_SIZE, 0, &skey);
	for (size pass = 0; pass < AAR_CRYPT_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			ubyte* t = dest + (AAR_BLOCK_SIZE * i);
			(void) aes_ecb_decrypt(t, t, &skey);
		}
	}
	aes_done(&skey);
#endif
}
