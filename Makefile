PROG=aar
SRCS=main.c contrib/aes256/aes256.c
CFLAGS+=-std=c99 -pedantic
.include <bsd.prog.mk>
