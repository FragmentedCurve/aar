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

bool
TruncateFile(file* fp, size offset)
{
	int fd = fileno(fp);
	bool result = ftruncate(fd, offset) != -1;
	fflush(fp);
	return result;
}

aes_key_ok
GenerateKey()
{
	aes_key_ok result = {0};
	file* fp = fopen("/dev/random", "rb");

	if (!fp) {
		goto error;
	}

	if (fread(&result.value, sizeof(byte), AAR_KEY_SIZE, fp) < AAR_KEY_SIZE) {
		goto error;
	}

	result.ok = 1;
	return result;

error:
	Println$("Failed to read from /dev/random.");
	fclose(fp);
	return result;
}
