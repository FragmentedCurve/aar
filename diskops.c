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

/* Call fclose if fp is not null, otherwise return 0. */
int
fclose_safe(file* fp)
{
	if (fp) {
		return fclose(fp);
	}
	return 0;
}

/* Return the byte length of a file. */
size
FileSize(file* fp)
{
	size file_length;
	size original_offset = ftell(fp);

	fseek(fp, 0, SEEK_END);
	file_length = ftell(fp);
	fseek(fp, original_offset, SEEK_SET);

	return file_length;
}

static void
InvertByteOrder(byte* buf, size blocksize, size blocks)
{
	while (blocks--) {
		byte* end = buf + blocksize - 1;
		while (buf < end) {
			// Swap
			*buf ^= *end;
			*end ^= *buf;
			*buf ^= *end;
			buf++, end--;
		}
	}
}

/*
  Convert endianness to big endian if we're on little endian
  architecture. This is analogous to htons(3).
 */
void
ToDisk(void* buf, size blocksize, size blocks)
{
	int endian_check = 1;
	int is_little = ((byte*)&endian_check)[0] == 1;

	if (is_little) {
		// We're little endians, we gotta get big!
		InvertByteOrder((byte*)buf, blocksize, blocks);
	}
}

/*
  Convert endianness to little endian if we're on little endian
  architecture. This is analogous to ntohs(3).
 */
void
FromDisk(void* buf, size blocksize, size blocks)
{
	ToDisk(buf, blocksize, blocks);
}

/*
  Shift an interval (x0, x1) of data within a file. If offset > 0, the
  data is shifted downwards to EOF. Otherwise, the data is shifted
  upward, towards the beginning of the file.

  Diagram of data displaying variables when data is being shifted
  downwards:

         /------- dx ----\
       x0                x1       EOF
  |.....|--|----|----|----|........|
                     \    /
                    chunk_size

  WARNING: Not thread-safe.
*/
void
ShiftFileData(file* fp, int offset, size x0, size x1)
{
	// Catch programming errors
	assert(x1 > x0);
	assert(fp);

	static byte chunk[AAR_IOBUF];
	size chunk_size = sizeof(chunk);
	size fsize = FileSize(fp);
	size dx = x1 - x0;

	bzero(chunk, chunk_size);

	// Nothing to do.
	if (x0 >= fsize || x1 <= 0 || offset == 0) {
		return;
	}

	// Data moved beyond x0 is truncated.
	if ((int)(x0 + offset) < 0) {
		x0 -= offset;
	}

	if (x1 > fsize) {
		x1 = fsize;
	}

	if (chunk_size > dx) {
		chunk_size = dx;
	}

	// Move full chunks
	for (size i = 0; i < dx / chunk_size; i++) {
		// Assume we're shifting down
		size chunk_position = x1 - (chunk_size * (i + 1));

		// Switch if we're shifting up
		if (offset < 0) {
			chunk_position = x0 + (chunk_size * i);
		}

		(void) fseek(fp, chunk_position, SEEK_SET);
		(void) fread(chunk, sizeof(byte), chunk_size, fp);
		(void) fseek(fp, chunk_position + offset, SEEK_SET);
		(void) fwrite(chunk, sizeof(byte), chunk_size, fp);
	}

	// If there's a partial chunk, move it
	chunk_size = dx - (dx / chunk_size) * chunk_size;
	if (chunk_size > 0) {
		size chunk_position = x0;
		if (offset < 0) {
			chunk_position = x1 - chunk_size;
		}

		(void) fseek(fp, chunk_position, SEEK_SET);
		(void) fread(chunk, sizeof(byte), chunk_size, fp);
		(void) fseek(fp, chunk_position + offset, SEEK_SET);
		(void) fwrite(chunk, sizeof(byte), chunk_size, fp);
	}

	// Removing trailing garbage if exists.
	if (x1 == fsize && offset < 0) {
		(void) fflush(fp);
		(void) TruncateFile(fp, fsize + offset);
	}

	(void) fflush(fp);

	// Set pointer to a reasonable location
	(void) fseek(fp, (offset > 0) ? x0 : x1, SEEK_SET);
}
