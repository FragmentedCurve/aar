PROG=aar
SRCS=build.c

AAR_CONF?= AAR_OS_POSIX AAR_CRYPT_LIBTOM

.for v in ${AAR_CONF}
${v}=
.endfor

${PROG}: git-submodules

CFLAGS+= -std=c99 -pedantic -I contrib/libtomcrypt/src/headers ${AAR_CONF:@cfg@-D${cfg}@}
# Debug build
.ifdef _AAR_DEBUG_NOCRYPT
CFLAGS+= -O0 -ggdb -pg
.else
CFLAGS+= -O2
.endif

# Build with libtomcrypt
.ifdef AAR_CRYPT_LIBTOM
.ifdef AAR_CRYPT_AES256
.error "You can't mix AAR_CRYPT_AES256 and AAR_CRYPT_LIBTOM."
.endif

LDADD+= contrib/libtomcrypt/libtomcrypt.a
${PROG}: contrib/libtomcrypt/libtomcrypt.a
contrib/libtomcrypt/libtomcrypt.a:
	make -C contrib/libtomcrypt/ CFLAGS="-D LTC_MINIMAL"
.endif

clean-contrib:
	make -C contrib/libtomcrypt/ clean
	make -C contrib/aes256/ clean

distclean: clean clean-contrib


git-submodules:
	git submodule init
	git submodule update

.include <bsd.prog.mk>
