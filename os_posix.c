bool
TruncateFile(file* fp, size offset)
{
	int fd = fileno(fp);
	return ftruncate(fd, offset) != -1;
}
