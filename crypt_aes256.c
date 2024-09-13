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
