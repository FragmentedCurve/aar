PROG=aar
SRCS=build.c contrib/aes256/aes256.c
CFLAGS+=-std=c99 -pedantic -D AAR_OS_POSIX
.ifdef DEBUG
CFLAGS+= -O0 -ggdb -pg -D _AAR_DEBUG_NOCRYPT
.else
CFLAGS+= -O2
.endif
.include <bsd.prog.mk>
