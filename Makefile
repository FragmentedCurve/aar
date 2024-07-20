PROG=aar
SRCS=build.c contrib/aes256/aes256.c
CFLAGS+=-std=c99 -pedantic
.ifdef DEBUG
CFLAGS+= -O0 -ggdb -pg -D _AAR_DEBUG_NOCRYPT 
.endif
.include <bsd.prog.mk>
