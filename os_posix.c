bool
TruncateFile(file* fp, size offset)
{
	int fd = fileno(fp);
	return ftruncate(fd, offset) != -1;
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
