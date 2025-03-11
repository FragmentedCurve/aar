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

// Global memory regions
struct {
	struct {
		aar_key raw;                      // 256 bit AES key for encrypting archive.
		aar_key encrypted[AAR_KEY_SIZE];  // Key in key_raw encrypted with itself.
		byte base64[AAR_BASE64_KEY_SIZE]; // Base64 encoded AES key (It's always 44 bytes long).
	} key;

	struct {
		string archive;  // Archive filename.
		string key;      // String object for mem.key.base64
	} stable;
} mem = {0};

aar_key_ok
GenerateKey()
{
	aar_key_ok result = {0};
	result.ok = RandomBytes((u8*) &result.value, AAR_KEY_SIZE);
	return result;
}

aar_checksum
Checksum(aar_checksum state, void* _buf, size buf_len)
{
	u8* buf = _buf;

	// 32-bit derivative of the BSD checksum.
	// (Performs better than CRC32 for us.)
	for (int i = 0; i < buf_len; i++) {
		state >>= 1;
		state += (state & 1) << 31;
		state += buf[i];
	}
	return state;
}

aar_checksum
ChecksumHdr(aar_hdr hdr)
{
	aar_checksum chk_hdr = AAR_CHECKSUM_INIT;

	chk_hdr = Checksum(chk_hdr, hdr.nonce, sizeof(hdr.nonce));
	chk_hdr = Checksum(chk_hdr, &hdr.data_length, sizeof(hdr.data_length));
	chk_hdr = Checksum(chk_hdr, &hdr.desc_length, sizeof(hdr.desc_length));

	return chk_hdr;
}

bool
IsValidHdr(aar_hdr hdr)
{
	return ChecksumHdr(hdr) == hdr.chk_hdr;
}

string
Base64EncodeKey(char* dest, aar_key k)
{
	base64_encode(dest, &k, AAR_KEY_SIZE);
	return $$$(dest, AAR_BASE64_KEY_SIZE);
}

aar_key_ok
Base64DecodeKey(string s)
{
	aar_key_ok result = {0};

	if (s.length != AAR_BASE64_KEY_SIZE) {
		return result;
	}

	if (base64_decoded_size(s.s, s.length) != AAR_KEY_SIZE) {
		return result;
	}

	if (!base64_valid(s.s, s.length)) {
		return result;
	}

	base64_decode(&result.value, s.s, s.length);

	result.ok = 1;
	return result;
}

void
WriteHdr(file* fout, aar_hdr hdr, aar_key key)
{
	u8 buf[AAR_HDR_MAX];
	u8* p = buf;
	size blocks = AAR_HDR_BLOCKS(hdr);
	size length = AAR_HDR_BYTES(hdr);

	bzero(buf, sizeof(buf));

	memcpy(p, hdr.desc, hdr.desc_length);
	p += AAR_PADDING(hdr.desc_length);

	ToDisk(&hdr.data_length, sizeof(hdr.data_length), 1);
	ToDisk(&hdr.desc_length, sizeof(hdr.desc_length), 1);
	ToDisk(&hdr.chk_hdr,     sizeof(hdr.chk_hdr),     1);
	ToDisk(&hdr.chk_desc,    sizeof(hdr.chk_desc),    1);
	ToDisk(&hdr.chk_data,    sizeof(hdr.chk_data),    1);

	memcpy(p, hdr.nonce, sizeof(hdr.nonce));
	p += sizeof(hdr.nonce);

	memcpy(p, &hdr.data_length, sizeof(hdr.data_length));
	p += sizeof(hdr.data_length);

	memcpy(p, &hdr.desc_length, sizeof(hdr.desc_length));
	p += sizeof(hdr.desc_length);

	memcpy(p, &hdr.chk_hdr, sizeof(hdr.chk_hdr));
	p += sizeof(hdr.chk_hdr);

	memcpy(p, &hdr.chk_desc, sizeof(hdr.chk_desc));
	p += sizeof(hdr.chk_desc);

	memcpy(p, &hdr.chk_data, sizeof(hdr.chk_data));

	EncryptBlocks(buf, blocks, key);
	fwrite(buf, sizeof(u8), length, fout);
	fflush(fout);
}

aar_hdr_ok
ReadHdr(file* fp, aar_key key)
{
	aar_hdr hdr;
	aar_hdr_ok result = {0};

	u8 buf[AAR_HDR_MAX];
	u8* p = buf;

	if (fread(buf, sizeof(u8), AAR_HDR_MIN, fp) != AAR_HDR_MIN) {
		return result;
	}

	DecryptBlocks(buf, AAR_HDR_MIN, key);

	memcpy(hdr.nonce, p, sizeof(hdr.nonce));
	p += sizeof(hdr.nonce);

	memcpy(&hdr.data_length, p, sizeof(hdr.data_length));
	p += sizeof(hdr.data_length);

	memcpy(&hdr.desc_length, p, sizeof(hdr.desc_length));
	p += sizeof(hdr.desc_length);

	memcpy(&hdr.chk_hdr, p, sizeof(hdr.chk_hdr));
	p += sizeof(hdr.chk_hdr);

	memcpy(&hdr.chk_desc, p, sizeof(hdr.chk_desc));
	p += sizeof(hdr.chk_desc);

	memcpy(&hdr.chk_data, p, sizeof(hdr.chk_data));

	FromDisk(&hdr.data_length, sizeof(hdr.data_length), 1);
	FromDisk(&hdr.desc_length, sizeof(hdr.desc_length), 1);
	FromDisk(&hdr.chk_hdr, sizeof(hdr.chk_hdr), 1);
	FromDisk(&hdr.chk_data, sizeof(hdr.chk_data), 1);
	FromDisk(&hdr.chk_desc, sizeof(hdr.chk_desc), 1);

	if (ChecksumHdr(hdr) != hdr.chk_hdr) {
		return result;
	}

	fseek(fp, -AAR_HDR_BYTES(hdr), SEEK_CUR);
	fread(buf, AAR_PADDING(hdr.desc_length), sizeof(u8), fp);
	DecryptBlocks(buf, AAR_BLOCKS(hdr.desc_length), key);
	memcpy(hdr.desc, buf, hdr.desc_length);

	if (Checksum(AAR_CHECKSUM_INIT, hdr.desc, hdr.desc_length) != hdr.chk_desc) {
		return result;
	}

	result.value = hdr;
	result.ok = 1;
	return result;
}

aar_hdr
NewHdr(file* fp, string desc)
{
	aar_hdr hdr = {0};

	if (desc.length >= AAR_DESC_MAX) {
		desc.length = AAR_DESC_MAX;
	}
	memcpy(hdr.desc, desc.s, desc.length);

	// Generate nonce
	RandomBytes(hdr.nonce, sizeof(hdr.nonce));

	hdr.data_length = FileSize(fp);
	hdr.desc_length = desc.length;
	hdr.chk_desc = Checksum(AAR_CHECKSUM_INIT, hdr.desc, hdr.desc_length);
	hdr.chk_hdr = ChecksumHdr(hdr);

	return hdr;
}

file*
ArchiveOpen(string filename)
{
	char path[filename.length + 1];

	bzero(path, sizeof(path));
	memcpy(path, filename.s, filename.length);

	return fopen(path, "r+");
}

file*
ArchiveCreate(string filename, aar_key key)
{
	file* fp;
	char path[filename.length + 1];
	aar_key encrypted_key;
	aar_hdr hdr = {0};
	string desc = $("END OF ARCHIVE");

	bzero(path, sizeof(path));
	memcpy(path, filename.s, filename.length);

	fp = fopen(path, "rb");
	if (fp) {
		Println$("File '%S' already exists. Refusing to overwrite.", path);
		fclose(fp);
		return NULL;
	}

	fp = fopen(path, "w+b");
	if (!fp) {
		Println$("Failed to create archive file.");
		return NULL;
	}

	RandomBytes(hdr.nonce, sizeof(hdr.nonce));
	snprintf(hdr.desc, AAR_DESC_MAX, "%s", desc.s);
	hdr.desc_length = desc.length;

	hdr.chk_hdr = ChecksumHdr(hdr);
	hdr.chk_desc = Checksum(AAR_CHECKSUM_INIT, hdr.desc, hdr.desc_length);
	WriteHdr(fp, hdr, key);

	return fp;
}

/*
void
IngestFile(file* fin, file* fout, aar_key key)
{
	size n;
	size buf_size = AAR_IOBUF;
	static u8 buf[AAR_IOBUF];
	aar_checksum chk = AAR_CHECKSUM_INIT;

	bzero(buf, buf_size);

	while (n = fread(buf, sizeof(u8), buf_size, fin), n > 0) {
		chk = Checksum(chk, buf, n);
		size blocks = AAR_BLOCKS(n);
		EncryptBlocks(buf, blocks, key);
		fwrite(buf, sizeof(u8), blocks * AAR_BLOCK_SIZE, fout);
		bzero(buf, buf_size);
	}

	ToDisk(&chk, sizeof(chk), 1);
	memcpy(buf, &chk, sizeof(chk));
	EncryptBlocks(buf, AAR_BLOCKS(sizeof(chk)), key);
	fwrite(buf, sizeof(u8), AAR_PADDING(sizeof(chk)), fout);
	fflush(fout);
}
*/

bool
SeekRecord(file* archive_file, size n, aar_key key)
{
	aar_hdr_ok hdr;

	fseek(archive_file, -AAR_HDR_MIN, SEEK_END);
	for (size i = 0; hdr = ReadHdr(archive_file, key), hdr.ok; i++) {
		if (i == n) {
			fseek(archive_file, -AAR_HDR_MIN, SEEK_CUR);
			return true;
		}
		fseek(archive_file, -(AAR_REC_BYTES(hdr.value) + AAR_HDR_MIN), SEEK_CUR);
	}

	return false;
}

void
EncryptFile(file* fp, string desc, aar_key key)
{
	int n;
	size buf_size = AAR_IOBUF;

	// WARNING: This function uses a static buffer for IO. It's not thread safe.
	static u8* buf[AAR_IOBUF];

	aar_hdr hdr = NewHdr(fp, desc);
	aar_checksum chk = AAR_CHECKSUM_INIT;

	bzero(buf, buf_size);

	while (n = fread(buf, sizeof(u8), buf_size, fp), n > 0) {
		chk = Checksum(chk, buf, n);
		(void) fseek(fp, -n, SEEK_CUR);
		size blocks = AAR_BLOCKS(n);
		EncryptBlocks(buf, blocks, key);
		(void) fwrite(buf, sizeof(u8), blocks * AAR_BLOCK_SIZE, fp);
		fflush(fp);
		bzero(buf, buf_size);
	}

	hdr.chk_data = chk;
	WriteHdr(fp, hdr, key);
	fflush(fp);
}

void
DecryptFile(file* fp, aar_key key)
{
	int n;
	size chk_count;
	size buf_size = AAR_IOBUF;
	aar_checksum chk = AAR_CHECKSUM_INIT;

	// WARNING: This function uses a static buffer for IO. It's not thread safe.
	static u8* buf[AAR_IOBUF];

	bzero(buf, buf_size);

	if (FileSize(fp) < AAR_HDR_MIN) {
		Println$("Invalid file.");
		return;
	}

	fseek(fp, -AAR_HDR_MIN, SEEK_END);
	aar_hdr_ok _hdr = ReadHdr(fp, key);
	if (!_hdr.ok) {
		Println$("Error: Not an AAR encrypted file.");
		return;
	}

	aar_hdr hdr = _hdr.value;
	if (FileSize(fp) != AAR_REC_BYTES(hdr)) {
		Println$("Error: File isn't a singular encrypted file. It's likely an archive. ");
		return;
	}

	rewind(fp);
	if (AAR_PADDING(hdr.data_length) < buf_size) {
		buf_size = AAR_PADDING(hdr.data_length);
	}
	chk_count = hdr.data_length;

	TruncateFile(fp, AAR_PADDING(hdr.data_length));
	fflush(fp);

	while (n = fread(buf, sizeof(u8), buf_size, fp), n > 0) {
		(void) fseek(fp, -n, SEEK_CUR);

		size blocks = AAR_BLOCKS(n);
		DecryptBlocks((byte*)buf, blocks, key);

		if (chk_count < n) {
			chk = Checksum(chk, buf, chk_count);
			chk_count = 0;
		} else {
			chk = Checksum(chk, buf, n);
			chk_count -= n;
		}

		(void) fwrite(buf, sizeof(u8), n, fp);
		fflush(fp);
		bzero(buf, buf_size);

		if (AAR_PADDING(hdr.data_length) < buf_size) {
			buf_size = AAR_PADDING(hdr.data_length);
		}
	}

	TruncateFile(fp, hdr.data_length);
	fflush(fp);

	if (chk != hdr.chk_data) {
		Println$("Error: Checksum failed -- Data is corrupted. ");
	}
}

void
ArchiveSplit(file* archive_file, size index, aar_key key)
{
/*
	aar_hdr_ok _hdr;
	if (!SeekRecord(archive_file, index, mem.key.raw)) {
		Println$("Warning: Record %d doesn't exist.", index);
		return;
	}

	if (_hdr = ReadRecord(archive_file, mem.key.raw), !_hdr.ok) {
		Println$("Record %d is corrupted.", index);
		return;
	}

	string desc = $$$(_hdr.value.desc, _hdr.value.desc_length);
	file* out = OpenFile(desc, "w+");
	if (!out) {
		Println$("Failed to extract record %d as '%s'", index, desc);
		return;
	}

	Println$("Splitting record %d as %s", index, desc);

	u8 buf[AAR_BLOCK_SIZE];
	WriteHdr(out, _hdr.value, mem.key.raw);
	for (size i = 0; i < _hdr.value.block_count + 1; i++) {
		bzero(buf, AAR_BLOCK_SIZE);
		(void) fread(buf, sizeof(u8), AAR_BLOCK_SIZE, archive_file);
		(void) fwrite(buf, sizeof(u8), AAR_BLOCK_SIZE, out);
		fflush(out);
	}
	fclose(out);
*/
}

void
ArchiveExtract(file* archive_file, size index, aar_key key)
{
/*
	aar_hdr_ok _hdr;
	if (!SeekRecord(archive_file, index, mem.key.raw)) {
		Println$("Warning: Record %d doesn't exist.", index);
		return;
	}

	if (_hdr = ReadRecord(archive_file, mem.key.raw), !_hdr.ok) {
		Println$("Record %d is corrupted.", index);
		return;
	}

	string desc = $$$(_hdr.value.desc, _hdr.value.desc_length);
	file* out = OpenFile(desc, "w+");
	if (!out) {
		Println$("Failed to extract record %d as '%s'", index, desc);
		return;
	}

	Println$("Extracting record %d as %s", index, desc);

	// TODO: Don't copy the record without
	// decrypting. We're passing over the data
	// twice...
	u8 buf[AAR_BLOCK_SIZE];
	WriteHdr(out, _hdr.value, mem.key.raw);
	for (size i = 0; i < _hdr.value.block_count + 1; i++) {
		bzero(buf, AAR_BLOCK_SIZE);
		(void) fread(buf, sizeof(u8), AAR_BLOCK_SIZE, archive_file);
		(void) fwrite(buf, sizeof(u8), AAR_BLOCK_SIZE, out);
		fflush(out);
	}

	// TODO: This is a waste of time. Just decrypt
	// data as writing it out.
	rewind(out);
	DecryptFile(out, mem.key.raw);
	fclose(out);
*/
}

void
Usage(string cmd)
{
	Println$("Usage:  %s [OPTIONS] COMMAND\n\n"

		 "Options:\n"
		 "  -k  --key=KEY       AES key encoded with base64.\n"
		 "  -a  --archive=FILE  AAR archive filename.\n\n"

		 "Archive Commands:\n"
		 "  new                          Generate a random AES-256 bit key.\n"
		 "  list                         List all file names.\n"
		 "  join     FILE [as DESC]...   Add files to an archive.\n"
		 "  remove   REC...              Delete a record.\n"
		 "  rename   [REC as DESC]       Change the description.\n"
		 "  extract  [REC...]            Extract a single record.\n"
		 "  split                        Divide the archive's records into individually encrypted files.\n"
		 "  note     DESC...             Insert a description log without data.\n\n"

		 "File Commands:\n"
		 "  rename   FILE as DESC...     Change the description.\n"
		 "  encrypt  FILE [as DESC]...   Encrypt a file without adding it to an archive.\n"
		 "  decrypt  REC [as DESC]...    Decrypt a file that's independent from an archive.", cmd);
}

#define shift(argc, argv) do { --argc; ++argv; } while(0);

string_ok
ParseAs(int argc, string* argv, size index)
{
	string_ok result = {0};

	if (argc - index >= 3 && Equals$("as", argv[index + 1])) {
		result.ok = 1;
		result.value = argv[index + 2];
	}

	return result;
}

int
Main(int argc, string* argv)
{
	aar_key_ok given_key = {0};

	if (argc <= 1) {
		Usage(argv[0]);
		exit(-1);
	}

	// Parse flags
	shift(argc, argv);
	while (argc > 0 && argv[0].s[0] == '-') {
		if (Equals$("-k", *argv)) {
			shift(argc, argv);
			if (argc < 1) {
				Println$("No key given.");
				exit(-1);
			}
			if (given_key = Base64DecodeKey(*argv), !given_key.ok) {
				Println$("Invalid key.");
				exit(-1);
			}
			memcpy(mem.key.base64, argv->s, argv->length);
			mem.stable.key = $$$(mem.key.base64, AAR_BASE64_KEY_SIZE);
			mem.key.raw = given_key.value;
		} else if (HasPrefix$("--key=", *argv)) {
			string k = Slice(*argv, $("--key=").length, argv[0].length);
			if (given_key = Base64DecodeKey(k), !given_key.ok) {
				Println$("Invalid key.");
				exit(-1);
			}
			memcpy(mem.key.base64, k.s, k.length);
			mem.stable.key = $$$(mem.key.base64, AAR_BASE64_KEY_SIZE);
			mem.key.raw = given_key.value;
		} else if (Equals$("-a", *argv)) {
			shift(argc, argv);
			if (argc < 1) {
				Println$("No archive filename given.");
				exit(-1);
			}
			mem.stable.archive = *argv;
		} else if (HasPrefix$("--archive=", *argv)) {
			mem.stable.archive = Slice(*argv, $("--archive=").length, argv[0].length);
			if (mem.stable.archive.length == 0) {
				Println$("No archive filename given.");
				exit(-1);
			}
		} else {
			Println$("Unknown flag '%s'.", *argv);
			exit(-1);
		}
		shift(argc, argv);
	}

	// No command given?
	if (argc == 0) {
		Println$("Give me something to do.");
		exit(-1);
	}

	// Parse command
	if (Equals$("new", *argv)) {
		// Generate a new key if one doesn't exist.
		if (mem.stable.key.length == 0) {
			if (given_key = GenerateKey(), !given_key.ok) {
				exit(-1);
			}
			mem.key.raw = given_key.value;
			mem.stable.key = Base64EncodeKey(mem.key.base64, given_key.value);
		}

		// Create an archive if one was provided.
		if (mem.stable.archive.length > 0) {
			file* fp = ArchiveCreate(mem.stable.archive, mem.key.raw);
			if (!fp) {
				exit(-1);
			}
			fclose(fp);
		}

		Println$("%s", mem.stable.key);
		exit(0);
	}

	// All other commands require a given key
	if (!given_key.ok) {
		Println$("A key must be given.");
		exit(-1);
	}

	if (Equals$("encrypt", *argv)) {
		shift(argc, argv);

		if (argc < 1) {
			Println$("No files to encrypt.");
			exit(0);
		}

		for (size i = 0; i < argc; i++) {
			string_ok _desc;

			string filename = argv[i];
			string desc = argv[i];

			file* fp = fopen(argv[i].s, "r+");

			if (_desc = ParseAs(argc, argv, i), _desc.ok) {
				desc = _desc.value;
				i += 2;
			}

			if (!fp) {
				Println$("Failed to open '%s'.", filename);
			} else {
				Println$("Encrypting '%s'", filename);
				EncryptFile(fp, desc, mem.key.raw);
			}
			fclose_safe(fp);
		}

		exit(0);
	} else if (Equals$("decrypt", *argv)) {
		shift(argc, argv);

		if (argc < 1) {
			Println$("No files to decrypt.");
			exit(0);
		}

		for (size i = 0; i < argc; i++) {
			file* fp = fopen(argv[i].s, "r+");
			if (!fp) {
				Println$("Failed to open '%s'.", argv[i]);
			} else {
				Println$("Decrypting '%s'", argv[i]);
				DecryptFile(fp, mem.key.raw);
				fclose(fp);
			}
		}

		exit(0);
	}

	// The rest of the commands require an opened archive.
	file* archive_file = ArchiveOpen(mem.stable.archive);
	if (!archive_file) {
		Println$("Failed to open archive file.");
		goto error;
	}

	if (!archive_file) {
		goto error;
	}

	// Continue parsing
	if (Equals$("add", *argv)) {
		/*
		shift(argc, argv);

		string filepath, desc;

		if (Equals(mem.stable.archive, argv[0])) {
			Println$("Error! An archive cannot ingest itself.");
			goto error;
		}

		if (argc < 1) {
			Println$("Error! Please supply a file to ingest and a description.");
			goto error;
		} else {
			filepath = argv[0];
		}

		if (argc >= 2) {
			desc  = argv[1];
		} else {
			desc = argv[0];
		}

		fseek(archive_file, 0, SEEK_END);

		// WARNING: filepath.s is safe because it came from main's argv
		file* ingest_file = fopen(filepath.s, "r");
		if (!ingest_file) {
			Println$("Failed to open '%s'.", filepath);
			goto error;
			}

		Println$("Ingesting '%s' from '%s'", desc, filepath);
		aar_hdr hdr = NewRecord(ingest_file, desc);

		WriteHdr(archive_file, hdr, mem.key.raw);
		IngestFile(ingest_file, archive_file, mem.key.raw);

		(void) fclose(ingest_file);
		*/
	} else if (Equals$("delete", *argv)) {
		shift(argc, argv);

		for (size i = 0; i < argc; i++) {
			size index = Atoi(argv[i]) - i;

			if (SeekRecord(archive_file, index, mem.key.raw)) {
				aar_hdr_ok _hdr = ReadHdr(archive_file, mem.key.raw);
				if (!_hdr.ok) {
					Println$("Error! Record index '%s' is corrupt. Aborting...", argv[i]);
					goto error;
				}

				aar_hdr hdr = _hdr.value;
				size record_length = AAR_HDR_BYTES(hdr) + AAR_DATA_BYTES(hdr);
				size x0 = ftell(archive_file) + AAR_DATA_BYTES(hdr);
				size x1 = FileSize(archive_file);

				Println$("Deleting %d %s", i, $$$(hdr.desc, hdr.desc_length));

				if (x0 == x1) {
					TruncateFile(archive_file, x1 - record_length);
				} else {
					ShiftFileData(archive_file, -record_length, x0, x1);
				}
			} else {
				Println$("Record index '%s' does not exist.", argv[i]);
			}
		}
	} else if (Equals$("list", *argv)) {
		aar_hdr_ok hdr;

		(void) fseek(archive_file, - AAR_HDR_MIN, SEEK_END);

		for (size i = 0; hdr = ReadHdr(archive_file, mem.key.raw), hdr.ok; i++) {
			printf("%4d %11d    ", i, hdr.value.data_length);
			fflush(stdout);
			Println($$$(hdr.value.desc, hdr.value.desc_length));
			if (fseek(archive_file, - AAR_REC_BYTES(hdr.value), SEEK_CUR) == -1) {
				// We went past the beginning of the file
				break;
			}
		}
	} else if (Equals$("extract", *argv) && argc == 1) {
		// Extract everything.
		for (size i = 0; SeekRecord(archive_file, i, mem.key.raw); i++) {
			ArchiveExtract(archive_file, i, mem.key.raw);
		}
	} else if (Equals$("extract", *argv)) {
		shift(argc, argv);
		for (size i = 0; i < argc; i++) {
			size index = Atoi(argv[i]);
			ArchiveExtract(archive_file, index, mem.key.raw);
		}
	} else if (Equals$("rename", *argv)) {
		shift(argc, argv);

		if (argc < 2) {
			Println$("Supply a record number and new record description.");
			goto error;
		}

		// TODO: Check if *argv is a number
		size index = Atoi(*argv);
		if (!SeekRecord(archive_file, index, mem.key.raw)) {
			Println$("Record '%s' doesn't exist.", *argv);
			goto error;
		}

		size pos = ftell(archive_file);
		aar_hdr_ok _hdr = ReadHdr(archive_file, mem.key.raw);
		if (!_hdr.ok) {
			Println$("Record '%d' is corrupted.", index);
			goto error;
		}

		aar_hdr hdr = _hdr.value;
		aar_hdr new_hdr = hdr;
		memcpy(new_hdr.desc, argv[1].s, argv[1].length);
		new_hdr.desc_length = argv[1].length;

		Println$("%d: %s -> %s", index, $$$(hdr.desc, hdr.desc_length), argv[1]);

		ShiftFileData(
			archive_file,
			AAR_HDR_BYTES(new_hdr) - AAR_HDR_BYTES(hdr),
			pos + AAR_HDR_BYTES(hdr),
			FileSize(archive_file));

		(void) fseek(archive_file, pos, SEEK_SET);
		WriteHdr(archive_file, new_hdr, mem.key.raw);
	} else if (Equals$("split", *argv)) {
		for (size i = 0; SeekRecord(archive_file, i, mem.key.raw); i++) {
			ArchiveSplit(archive_file, i, mem.key.raw);
		}
	} else if (Equals$("note", *argv)) {
		shift(argc, argv);

		aar_hdr hdr = {0};
		size offset = 0;

		for (size i = 0; i < argc; i++) {
			size n = argv[i].length;

			if (AAR_DESC_MAX - offset < n) {
				n = AAR_DESC_MAX - offset;
			}

			memcpy(hdr.desc + offset, argv[i].s, n);
			offset += n;
			if (i < argc - 1) {
				hdr.desc[offset] = ' ';
				offset++;
			}
		}

		hdr.desc_length = offset;
		hdr.chk_desc = Checksum(AAR_CHECKSUM_INIT, hdr.desc, offset);
		hdr.chk_hdr = ChecksumHdr(hdr);
		fseek(archive_file, 0, SEEK_END);
		WriteHdr(archive_file, hdr, mem.key.raw);
	} else {
		Println$("Unknown command: '%s'", *argv);
		goto error;
	}

	(void) fclose_safe(archive_file);
	exit(0);

error:
	(void) fclose_safe(archive_file);
	exit(-1);
}
