// Global memory regions
struct {
	struct {
		aes_key raw;                      // 256 bit AES key for encrypting archive.
		aes_key encrypted[AAR_KEY_SIZE];  // Key in key_raw encrypted with itself.
		byte base64[AAR_BASE64_KEY_SIZE]; // Base64 encoded AES key (It's always 44 bytes long).
	} key;

	struct {
		string archive;  // Archive filename.
		string key;      // String object for mem.key.base64
	} stable;
} mem = {0};

aar_checksum
Checksum(aar_checksum state, u8* buf, size buf_len)
{
	const u32 poly = 0xEDB88320;
	
	for (size i = 0; i < buf_len; i++) {
		state ^= buf[i];
		for (size bit = 0; bit < 8; bit++) {
			if (state & 1) {
				state = (state >> 1) ^ poly;
			} else {
				state >>= 1;
			}
		}
	}

	return ~state;
}

void
EncryptBlocks(byte* dest, size nblocks, aes_key key)
{
#ifndef _AAR_DEBUG_NOCRYPT
	aes256_context_t ctx;
	aes256_init(&ctx, (aes256_key_t*) &key);
	for (size pass = 0; pass < AAR_AES_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			aes256_encrypt_ecb(&ctx, ((aes256_blk_t*) dest) + i);
		}
	}
	aes256_done(&ctx);
#endif
}

void
DecryptBlocks(byte* dest, size nblocks, aes_key key)
{
#ifndef _AAR_DEBUG_NOCRYPT
	aes256_context_t ctx;
	aes256_init(&ctx, (aes256_key_t*) &key);
	for (size pass = 0; pass < AAR_AES_PASSES; pass++) {
		for (size i = 0; i < nblocks; i++) {
			aes256_decrypt_ecb(&ctx, ((aes256_blk_t*) dest) + i);
		}
	}
	aes256_done(&ctx);
#endif
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
		return result;
	}

	if (base64_decode(&result.value, s.s, AAR_BASE64_KEY_SIZE) != AAR_KEY_SIZE) {
		return result;
	}

	result.ok = 1;
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
	char path[filename.length + 1];

	memset(path, 0, sizeof(path));
	memcpy(path, filename.s, filename.length);

	return fopen(path, "r+");
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

	if (desc.length >= AAR_DESC_MAX) {
		desc.length = AAR_DESC_MAX;
	}
	memcpy(hdr.desc, desc.s, desc.length);

	size file_length = FileSize(fp);
	hdr.block_count = AAR_BLOCKS(file_length);
	hdr.block_offset = hdr.block_count * AAR_BLOCK_SIZE - file_length;
	hdr.desc_length = desc.length;

	return hdr;
}

void
WriteRecord(file* fout, aar_record_header hdr, aes_key key)
{
	// We require 2 extra blocks for potentially padding the min
	// section and the desc section.
	u8 buf[AAR_RECORD_MAX + 2 * AAR_CHECKSUM_SIZE + 2 * AAR_BLOCK_SIZE];
	size min_bytes = AAR_PADDING(AAR_RECORD_MIN + AAR_CHECKSUM_SIZE);
	size desc_bytes = AAR_PADDING(hdr.desc_length + AAR_CHECKSUM_SIZE);
	aar_checksum chk_hdr = AAR_CHECKSUM_INIT;
	aar_checksum chk_desc = AAR_CHECKSUM_INIT;

	memset(buf, 0, sizeof(buf));

	if (hdr.desc_length == 0) {
		desc_bytes = 0;
	}
	
	{ // Compute checksums
		chk_hdr = Checksum(chk_hdr, (u8*)&hdr.block_count, sizeof(hdr.block_count));
		chk_hdr = Checksum(chk_hdr, (u8*)&hdr.block_offset, sizeof(hdr.block_offset));
		chk_hdr = Checksum(chk_hdr, (u8*)&hdr.desc_length, sizeof(hdr.desc_length));
		chk_desc = Checksum(chk_desc, (u8*)hdr.desc, hdr.desc_length);

		ToDisk((byte*)&chk_hdr, sizeof(chk_hdr), 1);
		ToDisk((byte*)&chk_desc, sizeof(chk_desc), 1);
	}
	
	{ // Copy desc first
		memcpy(buf + min_bytes, hdr.desc, hdr.desc_length);
		memcpy(buf + min_bytes + hdr.desc_length, &chk_desc, AAR_CHECKSUM_SIZE);
	}
	
	ToDisk((byte*)&hdr.block_count, sizeof(hdr.block_count), 1);
	ToDisk((byte*)&hdr.block_offset, sizeof(hdr.block_offset), 1);
	ToDisk((byte*)&hdr.desc_length, sizeof(hdr.desc_length), 1);
		
	{ // Copy header data
		u8* p = buf;

		memcpy(buf, &hdr.block_count, sizeof(hdr.block_count));
		p += sizeof(hdr.block_count);
		memcpy(p, &hdr.block_offset, sizeof(hdr.block_offset));
		p += sizeof(hdr.block_offset);
		memcpy(p, &hdr.desc_length, sizeof(hdr.desc_length));
		p += sizeof(hdr.desc_length);
		memcpy(p, &chk_hdr, AAR_CHECKSUM_SIZE);
	}
	
	EncryptBlocks(buf, AAR_BLOCKS(min_bytes + desc_bytes), key);

	fwrite(buf, sizeof(u8), min_bytes + desc_bytes, fout);
	fflush(fout);
}

void
IngestFile(file* fin, file* fout, aes_key key)
{
	size n;
	u8 buf[1024 * AAR_BLOCK_SIZE] = {0};
	aar_checksum chk = AAR_CHECKSUM_INIT;
	
	while (n = fread(buf, sizeof(u8), sizeof(buf), fin), n > 0) {
		chk = Checksum(chk, buf, n);
		
		size blocks = AAR_BLOCKS(n);
		EncryptBlocks(buf, blocks, key);
		fwrite(buf, sizeof(u8), blocks * AAR_BLOCK_SIZE, fout);
		memset(buf, 0, sizeof(buf));
	}

	// TODO: Append data checksum
}

aar_record_header_ok
ReadRecord(file* archive_file, aes_key key)
{
	aar_record_header hdr;
	aar_record_header_ok result = {0};
	
	// Only one padding block is required here. We can ignore the
	// padding at the end of desc.
	u8 buf[AAR_RECORD_MAX + 2 * AAR_CHECKSUM_SIZE + AAR_BLOCK_SIZE];
	u8* p = buf;

	size pos = ftell(archive_file);
	size min_bytes = AAR_PADDING(AAR_RECORD_MIN + AAR_CHECKSUM_SIZE);

	aar_checksum chk_hdr = 0;
	aar_checksum chk_desc = 0;

	{ // Clear all buffers
		memset(&hdr, 0, sizeof(hdr));
		memset(buf, 0, sizeof(buf));
	}

	// Read as much as possible. Garbage at the end will be ignored.
	if (fread(buf, sizeof(u8), sizeof(buf), archive_file) < AAR_PADDING(AAR_RECORD_MIN + AAR_CHECKSUM_SIZE)) {
		// TODO: Return EOF error.
		return result;
	}
	DecryptBlocks(buf, AAR_BLOCKS(min_bytes), key);

	{ // Copy data into our record struct
		memcpy(&hdr.block_count, p, sizeof(hdr.block_count));
		p += sizeof(hdr.block_count);

		memcpy(&hdr.block_offset, p, sizeof(hdr.block_offset));
		p += sizeof(hdr.block_offset);

		memcpy(&hdr.desc_length, p, sizeof(hdr.desc_length));
		p += sizeof(hdr.desc_length);

		memcpy(&chk_hdr, p, AAR_CHECKSUM_SIZE);
		p = buf + min_bytes; // Jump to the start of hdr.desc
	}

	{ // Correct the data for endianness
		FromDisk((byte*)&chk_hdr, AAR_CHECKSUM_SIZE, 1);
		FromDisk((byte*)&hdr.block_offset, sizeof(hdr.block_offset), 1);
		FromDisk((byte*)&hdr.block_count, sizeof(hdr.block_count), 1);
		
		// We need this before we can read in hdr.desc
		FromDisk((byte*)&hdr.desc_length, sizeof(hdr.desc_length), 1);
	}

	{ // Check for corruption before reading hdr.desc
		aar_checksum _chk_hdr = Checksum(AAR_CHECKSUM_INIT, (u8*) &hdr.block_count, sizeof(hdr.block_count));
		_chk_hdr = Checksum(_chk_hdr, (u8*) &hdr.block_offset, sizeof(hdr.block_offset));
		_chk_hdr = Checksum(_chk_hdr, (u8*) &hdr.desc_length, sizeof(hdr.desc_length));

		if (chk_hdr != _chk_hdr) {
			// TODO: Return corruption error.
			return result;
		}
	}

	DecryptBlocks(p, AAR_BLOCKS(hdr.desc_length + AAR_CHECKSUM_SIZE), key);
	memcpy(&chk_desc, p + hdr.desc_length, AAR_CHECKSUM_SIZE);
	FromDisk((byte*)&chk_desc, AAR_CHECKSUM_SIZE, 1);

	// Copy only the desc data while ignoring the potential
	// garbage at the end.
	memcpy(hdr.desc, p, hdr.desc_length);
		
	{ // Check for corruption
		aar_checksum _chk_desc = Checksum(AAR_CHECKSUM_INIT, hdr.desc, hdr.desc_length);

		if (chk_desc != _chk_desc && hdr.desc_length != 0) {
			// TODO: Return corruption error.
			return result;
		}
	}

	// Set the cursor position as the end of record header/beginning of data
	(void) fseek(archive_file, pos + AAR_HDR_BYTES(hdr), SEEK_SET);

	result.ok = 1;
	result.value = hdr;
	return result;
}

bool
SeekRecord(file* archive_file, size n)
{
	aar_record_header_ok hdr;

	fseek(archive_file, AAR_FILE_HEADER_SIZE, SEEK_SET);
	for (size i = 0; hdr = ReadRecord(archive_file, mem.key.raw), hdr.ok; i++) {
		if (i == n) {
			fseek(archive_file, -AAR_HDR_BYTES(hdr.value), SEEK_CUR);
			return true;
		}
		fseek(archive_file, AAR_DATA_BYTES(hdr.value), SEEK_CUR);
	}

	return false;
}

void
EncryptFile(file* fp, aes_key key)
{
	int n;
	u8 buf[1024 * AAR_BLOCK_SIZE] = {0};
	aar_record_header hdr = NewRecord(fp, $("")); // TODO: Replace empty string with file name
	
	ShiftFileData(fp, AAR_PADDING(AAR_RECORD_MIN + AAR_CHECKSUM_SIZE), 0, FileSize(fp));
	WriteRecord(fp, hdr, key);
	fflush(fp);

	while (n = fread(buf, sizeof(u8), sizeof(buf), fp), n > 0) {
		(void) fseek(fp, -n, SEEK_CUR);
		size blocks = AAR_BLOCKS(n);
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

	aar_record_header_ok _hdr = ReadRecord(fp, key);
	if (!_hdr.ok) {
		Println$("Error: Not an AAR encrypted file.");
		return;
	}

	aar_record_header hdr = _hdr.value;
	ShiftFileData(fp, -AAR_PADDING(AAR_RECORD_MIN), 0, FileSize(fp));
	rewind(fp);

	while (n = fread(buf, sizeof(u8), sizeof(buf), fp), n > 0) {
		(void) fseek(fp, -n, SEEK_CUR);
		size blocks = AAR_BLOCKS(n);
		DecryptBlocks(buf, blocks, key);
		(void) fwrite(buf, sizeof(u8), blocks * AAR_BLOCK_SIZE, fp);
		fflush(fp);
		memset(buf, 0, sizeof(buf));
	}

	int fd = fileno(fp);
	(void) ftruncate(fd, FileSize(fp) - hdr.block_offset);
	fflush(fp);
}

void
Extract(file* archive_file, size index, aes_key key)
{
	// TODO: Implement me.
}

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
		 "  add       Add files to an archive.\n"
		 "  delete    Delete a record.\n"
		 "  extract   Extract all files.\n"
		 "  validate  Check for file corruption.\n"
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
		Println$("Failed to open archive file.");
		goto error;
	}

	if (!archive_file) {
		goto error;
	}

	if (given_key = ArchiveValidate(archive_file, mem.key.raw), !given_key.ok) {
		Println$("Key doesn't match archive's key.");
		goto error;
	}

	// Continue parsing
	if (Equals$("add", *argv)) {
		shift(argc, argv);

		if (Equals(mem.stable.archive, argv[0])) {
			Println$("Error! An archive cannot ingest itself.");
			goto error;
		}
		
		if (argc < 2) {
			Println$("Error! Please supply a file to ingest and a description.");
			goto error;
		}

		fseek(archive_file, 0, SEEK_END);

		file* ingest_file = fopen(argv[0].s, "r");
		if (!ingest_file) {
			Println$("Failed to open '%s'.", argv[0]);
			goto error;
		}

		Println$("Ingesting '%s' from '%s'", argv[1], argv[0]);
		aar_record_header hdr = NewRecord(ingest_file, argv[1]);
		
		WriteRecord(archive_file, hdr, mem.key.raw);
		IngestFile(ingest_file, archive_file, mem.key.raw);

		(void) fclose(ingest_file);
	} else if (Equals$("delete", *argv)) {
		shift(argc, argv);

		for (size i = 0; i < argc; i++) {
			size index = Atoi(argv[i]) - i;
			
			if (SeekRecord(archive_file, index)) {
				aar_record_header_ok _hdr = ReadRecord(archive_file, mem.key.raw);
				if (!_hdr.ok) {
					Println$("Error! Record index '%s' is corrupt. Aborting...", argv[i]);
					goto error;
				}
				
				aar_record_header hdr = _hdr.value;
				size record_length = AAR_HDR_BYTES(hdr) + AAR_DATA_BYTES(hdr);
				size x0 = ftell(archive_file) + AAR_DATA_BYTES(hdr);
				size x1 = FileSize(archive_file);

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
		fseek(archive_file, AAR_KEY_SIZE, SEEK_SET);

		aar_record_header_ok hdr;
		for (size i = 0; hdr = ReadRecord(archive_file, mem.key.raw), hdr.ok; i++) {
			Println$("%d    %s", i, $$$(hdr.value.desc, hdr.value.desc_length));
			fseek(archive_file, AAR_DATA_BYTES(hdr.value), SEEK_CUR);
		}
	} else if (Equals$("extract", *argv)) {
		shift(argc, argv);

		// TODO: Extract only selected files.
		
		aar_record_header_ok hdr;
		for (size i = 0; hdr = ReadRecord(archive_file, mem.key.raw), hdr.ok; i++) {
			
		}
	} else {
		Println$("Unknown command: '%s'", *argv);
		goto error;
	}


	exit(0);
	
error:
	(void) fclose_safe(archive_file);
	exit(-1);
}
