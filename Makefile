# Copyright (c) 2024 Paco Pascal <me@pacopascal.com>
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

PROG=aar
SRCS=build.c
MODULES=contrib/aes256 contrib/libtomcrypt

AAR_CONF= AAR_OS_POSIX AAR_CRYPT_LIBTOM # _AAR_DEBUG_NOCRYPT

.for v in ${AAR_CONF}
${v}=
.endfor

CFLAGS+= -std=c99 -pedantic -Wall ${AAR_CONF:@cfg@-D${cfg}@} \
	-Wno-gnu-zero-variadic-macro-arguments \
	-Wno-dollar-in-identifier-extension

# Debug build
.ifdef _AAR_DEBUG_NOCRYPT
CFLAGS+= -O0 -ggdb -pg
.else
CFLAGS+= -O2
.endif

# TODO: Automate configuring these vars
BSDMAKE?=${MAKE}
GNUMAKE?=gmake
EMACS?=emacs

${PROG}: ${MODULES}

# Build with libtomcrypt
.ifdef AAR_CRYPT_AES256 && AAR_CRYPT_LIBTOM
.error "You can't mix AAR_CRYPT_AES256 and AAR_CRYPT_LIBTOM."
.elifdef AAR_CRYPT_LIBTOM
CFLAGS+= -I contrib/libtomcrypt/src/headers
LDADD+= contrib/libtomcrypt/libtomcrypt.a
${PROG}: contrib/libtomcrypt/libtomcrypt.a
contrib/libtomcrypt/libtomcrypt.a:
	${GNUMAKE} -C contrib/libtomcrypt/ CFLAGS="-D LTC_MINIMAL -fPIC"
.endif

clean-contrib:
	${GNUMAKE} -C contrib/libtomcrypt/ clean
	${GNUMAKE} -C contrib/aes256/ clean

distclean: clean clean-contrib

${MODULES}:
	@git submodule init
	@git submodule update

README README.md: README.org
	${EMACS} -Q --batch --script readme.el

test: ${PROG}
	${BSDMAKE} -C tests

.PHONY: test distclean clean-contrib

.include <bsd.prog.mk>
