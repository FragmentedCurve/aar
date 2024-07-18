#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>

#include "typeok.h"
#define NSTRINGS_MAIN
#include "nstrings.h"
#include "base64.h"

#define BACK_TO_TABLES // Use pre-calculated tables for AES
#include "contrib/aes256/aes256.h"

#include "aarfmt.h"

#define _ (void)

/*
  TODO: Maybe use error types.

typedef const struct { string msg; int ok; } error;
#define Error(m) ((error){m, 0})
#define Error$(m) Error($(m))

error ErrArchiveExists = Error$("Archive already exists.");
error ErrInvalidKey    = Error$("Key isn't a valid aar AES key.");
error ErrIncorrectKey  = Error$("The given AES key doesn't match the archive.");
*/

// Global memory regions
struct {
	struct {
		aes_key raw;                      // 256 bit AES key for encrypting archive.
		aes_key encrypted[AAR_KEY_SIZE];  // Key in key_raw encrypted with itself.
		byte base64[AAR_BASE64_KEY_SIZE]; // Base64 encoded AES key (It's always 44 bytes long).
	} key;

	struct {
		string archive;               // Archive filename.
		string key;                   // String object for mem.key.base64
	} stable;
} mem = {0};

#include "diskops.c"

void
EncryptBlocks(byte* dest, size nblocks, aes_key key)
{
	aes256_context_t ctx;
	aes256_init(&ctx, (aes256_key_t*) &key);
	for (size pass = 0; pass < AAR_AES_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			aes256_encrypt_ecb(&ctx, ((aes256_blk_t*) dest) + i);
		}
	}
	aes256_done(&ctx);
}

void
DecryptBlocks(byte* dest, size nblocks, aes_key key)
{
	aes256_context_t ctx;
	aes256_init(&ctx, (aes256_key_t*) &key);
	for (size pass = 0; pass < AAR_AES_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			aes256_decrypt_ecb(&ctx, ((aes256_blk_t*) dest) + i);
		}
	}
	aes256_done(&ctx);
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

string
Base64EncodeKey(char* dest, aes_key k)
{
	base64_encode(dest, &k, AAR_KEY_SIZE);
	return $$$(dest, AAR_BASE64_KEY_SIZE);
}

aes_key_ok
Base64DecodeKey(string s)
{
	aes_key_ok result = {0};

	if (base64_valid(s.s, s.length)) {
		goto error;
	}

	if (base64_decode(&result.value, s.s, AAR_BASE64_KEY_SIZE) != AAR_KEY_SIZE) {
		goto error;
	}

	result.ok = 1;
error:
	return result;
}

aes_key_ok
ArchiveValidate(file* fp, aes_key given_key)
{
	aes_key_ok archive_key = {0};

	if (fread(&archive_key.value, AAR_KEY_SIZE, 1, fp) != 1) {
		Println$("Failed to read key.");
		return archive_key;
	}
	
	DecryptBlocks((byte*) &archive_key.value, 2, given_key);
	archive_key.ok = memcmp(&archive_key.value, &given_key, AAR_KEY_SIZE) == 0;

	return archive_key;
}

file*
ArchiveOpen(string filename)
{
	file* result = NULL;
	char path[filename.length + 1];

	memset(path, 0, sizeof(path));
	memcpy(path, filename.s, filename.length);

	result = fopen(path, "r+");
	if (!result) {
		Println$("Failed to open archive file.");
		return result;
	}

	return result;
}

file*
ArchiveCreate(string filename, aes_key key)
{
	file* fp;
	char path[filename.length + 1];
	aes_key encrypted_key;
	
	memset(path, 0, sizeof(path));
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

	encrypted_key = key;
	EncryptBlocks((byte*) &encrypted_key, 2, key);

	if (fwrite(&encrypted_key, sizeof(byte), AAR_KEY_SIZE, fp) < AAR_KEY_SIZE) {
		Println$("Failed to write data to archive file.");
		fclose(fp);
		return NULL;
	}

	return fp;
}

aar_record_header
NewRecord(file* fp, string desc)
{
	aar_record_header hdr = {0};

	if (desc.length >= AAR_PATH_MAX) {
		desc.length = AAR_PATH_MAX;
	}
	memcpy(hdr.desc, desc.s, desc.length);

	size file_length = FileSize(fp);
	hdr.block_count = BytesToBlocks(file_length);
	hdr.block_offset = hdr.block_count * AAR_BLOCK_SIZE - file_length;
	hdr.desc_size = desc.length;

	return hdr;
}

void
WriteRecord(file* fout, aar_record_header hdr, aes_key key)
{
	// We require 2 extra blocks for potentially padding the min
	// section and the desc section.
	u8 buf[AAR_RECORD_MAX + 2 * AAR_BLOCK_SIZE];
	u8* p = buf;
	size desc_size = hdr.desc_size;
	size min_bytes = AAR_RECORD_MIN + BytesToPadding(AAR_RECORD_MIN);
	size desc_bytes = desc_size + BytesToPadding(desc_size);

	memset(buf, 0, sizeof(buf));
	
	ToDisk((byte*)&hdr.block_count, sizeof(hdr.block_count), 1);
	ToDisk((byte*)&hdr.block_offset, sizeof(hdr.block_offset), 1);
	ToDisk((byte*)&hdr.desc_size, sizeof(hdr.desc_size), 1);

	memcpy(buf, &hdr.block_count, sizeof(hdr.block_count));
	p += sizeof(hdr.block_count);
	memcpy(p, &hdr.block_offset, sizeof(hdr.block_offset));
	p += sizeof(hdr.block_offset);
	memcpy(p, &hdr.desc_size, sizeof(hdr.desc_size));
	p += sizeof(hdr.desc_size);

	p = buf + min_bytes;
	memcpy(p, hdr.desc, desc_size);

	EncryptBlocks(buf, AAR_BLOCKS(AAR_RECORD_MIN), key);

	fwrite(buf, sizeof(u8), min_bytes + desc_bytes, fout);
	fflush(fout);
}

void
IngestFile(file* fin, file* fout, aes_key key)
{
	size n;
	u8 buf[1024 * AAR_BLOCK_SIZE] = {0};

	while (n = fread(buf, sizeof(u8), sizeof(buf), fin), n > 0) {
		size blocks = BytesToBlocks(n);
		EncryptBlocks(buf, blocks, key);
		fwrite(buf, sizeof(u8), blocks * AAR_BLOCK_SIZE, fout);
		memset(buf, 0, sizeof(buf));
	}
}

size
FullRecordHeaderSize(aar_record_header hdr)
{
	return AAR_RECORD_MIN + BytesToPadding(AAR_RECORD_MIN) + hdr.desc_size + BytesToPadding(hdr.desc_size);
}

size
FullRecordSize(aar_record_header hdr)
{
	return FullRecordHeaderSize(hdr) + hdr.block_count * AAR_BLOCK_SIZE;
}

aar_record_header
ReadRecord(file* archive_file, aes_key key)
{
	aar_record_header hdr;
	
	// Only one padding block is required here. We can ignore the
	// padding at the end of desc.
	u8 buf[AAR_RECORD_MAX + AAR_BLOCK_SIZE];

	u8* p = buf;
	size pos = ftell(archive_file);
	size min_bytes = AAR_RECORD_MIN + BytesToPadding(AAR_RECORD_MIN);

	{ // Clear all buffers
		memset(&hdr, 0, sizeof(hdr));
		memset(buf, 0, sizeof(buf));
	}
	
	// Read as much as possible. Garbage at the end will be ignored.
	(void) fread(buf, sizeof(u8), sizeof(buf), archive_file);
	DecryptBlocks(buf, AAR_BLOCKS(AAR_RECORD_MIN), key);

	{ // Copy data into our record struct
		memcpy(&hdr.block_count, p, sizeof(hdr.block_count));
		p += sizeof(hdr.block_count);

		memcpy(&hdr.block_offset, p, sizeof(hdr.block_offset));
		p += sizeof(hdr.block_offset);

		memcpy(&hdr.desc_size, p, sizeof(hdr.desc_size));
		p = buf + min_bytes; // Jump to the start of hdr.desc
	}

	{ // Correct the data for endianness
		FromDisk((byte*)&hdr.block_offset, sizeof(hdr.block_offset), 1);
		FromDisk((byte*)&hdr.block_count, sizeof(hdr.block_count), 1);

		// We need this before we can read in hdr.desc
		FromDisk((byte*)&hdr.desc_size, sizeof(hdr.desc_size), 1);
	}

	// Copy only the desc data while ignoring the potential
	// garbage at the end.
	memcpy(hdr.desc, p, hdr.desc_size);
	DecryptBlocks(hdr.desc, AAR_BLOCKS(hdr.desc_size), key);

	// Set the cursor position as the end of record header/beginning of data
	fseek(archive_file, pos + FullRecordHeaderSize(hdr), SEEK_SET);
	
	return hdr;
}

aar_record_header_ok
ReadRecordOK(file* archive_file, aes_key key)
{
	aar_record_header_ok hdr = {0};

	size position = ftell(archive_file);
	size file_length = FileSize(archive_file);

	if (file_length - position < AAR_RECORD_MIN) {
		return hdr;
	}

	hdr.value = ReadRecord(archive_file, key);
	hdr.ok = 1;
	
	return hdr;
}

bool
SeekRecord(file* archive_file, size n)
{
	aar_record_header_ok hdr;

	fseek(archive_file, AAR_FILE_HEADER_SIZE, SEEK_SET);
	for (size i = 0; hdr = ReadRecordOK(archive_file, mem.key.raw), hdr.ok; i++) {
		if (i == n) {
			fseek(archive_file, AAR_RECORD_MAX, SEEK_CUR);
			return true;
		}
		fseek(archive_file, hdr.value.block_count * AAR_BLOCK_SIZE, SEEK_CUR);
	}

	return false;
}

void
EncryptFile(file* fp, aes_key key)
{
	int n;
	u8 buf[1024 * AAR_BLOCK_SIZE] = {0};
	aar_record_header hdr = NewRecord(fp, $("")); // TODO: Replace empty string with file name
	
	ShiftFileData(fp, AAR_RECORD_MIN + BytesToPadding(AAR_RECORD_MIN), 0, FileSize(fp));
	WriteRecord(fp, hdr, key);
	fflush(fp);
	
	while (n = fread(buf, sizeof(u8), sizeof(buf), fp), n > 0) {
		(void) fseek(fp, -n, SEEK_CUR);
		size blocks = BytesToBlocks(n);
		EncryptBlocks(buf, blocks, key);
		(void) fwrite(buf, sizeof(u8), blocks * AAR_BLOCK_SIZE, fp);
		fflush(fp);
		memset(buf, 0, sizeof(buf));
	}
}

void
DecryptFile(file* fp, aes_key key)
{
	// TODO: Ensure this doesn't need better error checking.
	int n;
	u8 buf[1024 * AAR_BLOCK_SIZE] = {0};

	if (FileSize(fp) < AAR_RECORD_MIN) {
		Println$("Invalid file.");
		return;
	}
	
	aar_record_header hdr = ReadRecord(fp, key);
	ShiftFileData(fp, -(AAR_RECORD_MIN + BytesToPadding(AAR_RECORD_MIN)), 0, FileSize(fp));
	rewind(fp);

	while (n = fread(buf, sizeof(u8), sizeof(buf), fp), n > 0) {
		(void) fseek(fp, -n, SEEK_CUR);
		size blocks = BytesToBlocks(n);
		DecryptBlocks(buf, blocks, key);
		(void) fwrite(buf, sizeof(u8), blocks * AAR_BLOCK_SIZE, fp);
		fflush(fp);
		memset(buf, 0, sizeof(buf));
	}
	
	int fd = fileno(fp);
	(void) ftruncate(fd, FileSize(fp) - hdr.block_offset);
	fflush(fp);
}

/*
void
Extract(file* archive_file, aes_key key)
{
	aar_record_hdr hdr = ReadRecord(archive_file, key);
	file* fout = fopen();
}

void
ExtractAll(file* archive_file, aes_key key)
{
	
}

void
ExtractRecords(file* archive_file, int* index, size n, aes_key key)
{
	
}
*/

void
Usage(string cmd)
{
	Println$("Usage:  %s [OPTIONS] COMMAND\n\n"

		 "Options:\n"
		 "  -k  --key=KEY       AES key encoded with base64.\n"
		 "  -a  --archive=FILE  AAR archive filename.\n\n"

		 "Commands:\n"
		 "  new       Generate a random AES-256 bit key.\n"
		 "  list      List all file names.\n"
		 "  ingest    Insert a new file.\n"
		 "  extract   Extract all files.\n"
		 "  encrypt   Encrypt a file without adding it to an archive.\n"
		 "  decrypt   Decrypt a file that's independent from an archive.", cmd);
}

#define shift(argc, argv) do { --argc; ++argv; } while(0);

int
Main(int argc, string* argv)
{
	aes_key_ok given_key = {0};
	
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
		} else {
			Println$("Unknown flag '%s'.", *argv);
			exit(-1);
		}
		shift(argc, argv);
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
	} else if (Equals$("encrypt", *argv)) {
		shift(argc, argv);

		if (argc < 1) {
			Println$("No files to encrypt.");
			exit(0);
		}

		for (size i = 0; i < argc; i++) {
			file* fp = fopen(argv[i].s, "r+");
			if (!fp) {
				Println$("Failed to open '%s'.", argv[i]);
			} else {
				Println$("Encrypting '%s' ...", argv[i]);
				EncryptFile(fp, mem.key.raw);
				fclose(fp);
			}
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
				Println$("Decrypting '%s' ...", argv[i]);
				DecryptFile(fp, mem.key.raw);
				fclose(fp);
			}
		}
		
		exit(0);
	}

	// The rest of the commands require an opened archive.

	file* archive_file = ArchiveOpen(mem.stable.archive);

	if (!archive_file) {
		exit(-1);
	}
	
	if (given_key = ArchiveValidate(archive_file, mem.key.raw), !given_key.ok) {
		Println$("Key doesn't match archive's key.");
		fclose(archive_file);
		exit(-1);
	}

	// Continue parsing
	if (Equals$("ingest", *argv)) {
		shift(argc, argv);

		if (argc < 2) {
			Println$("Please supply a file to ingest and a description.");
			exit(-1);
		}

		fseek(archive_file, 0, SEEK_END);

		file* ingest_file = fopen(argv[0].s, "r");
		// TODO: Check if fopen failed.
		aar_record_header hdr = NewRecord(ingest_file, argv[1]);
		
		WriteRecord(archive_file, hdr, mem.key.raw);
		IngestFile(ingest_file, archive_file, mem.key.raw);
		
		fclose(ingest_file);
	} else if (Equals$("list", *argv)) {
		fseek(archive_file, AAR_KEY_SIZE, SEEK_SET);

		aar_record_header_ok hdr;
		for (size i = 0; hdr = ReadRecordOK(archive_file, mem.key.raw), hdr.ok; i++) {
			Println$("%d    %s", i, $$$(hdr.value.desc, hdr.value.desc_size));
			fseek(archive_file, hdr.value.block_count * AAR_BLOCK_SIZE, SEEK_CUR);
		}
	} else if (Equals$("extract", *argv)) {
		shift(argc, argv);

		// TODO: Extract only selected files.
		
		aar_record_header_ok hdr;
		for (size i = 0; hdr = ReadRecordOK(archive_file, mem.key.raw), hdr.ok; i++) {
			
		}
	} else {
		Println$("Unknown command: '%s'", *argv);
	}

	fclose(archive_file);
	exit(0);
}
