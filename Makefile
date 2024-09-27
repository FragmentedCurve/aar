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

AAR_CONF= AAR_OS_POSIX AAR_CRYPT_LIBTOM

.for v in ${AAR_CONF}
${v}=
.endfor

${PROG}: git-submodules

CFLAGS+= -std=c99 -pedantic -Wall ${AAR_CONF:@cfg@-D${cfg}@}

# Debug build
.ifdef _AAR_DEBUG_NOCRYPT
CFLAGS+= -O0 -ggdb -pg
.else
CFLAGS+= -O2
.endif

# Build with libtomcrypt
.ifdef AAR_CRYPT_AES256 && AAR_CRYPT_LIBTOM
.error "You can't mix AAR_CRYPT_AES256 and AAR_CRYPT_LIBTOM."
.elifdef AAR_CRYPT_LIBTOM
CFLAGS+= -I contrib/libtomcrypt/src/headers
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
	@git submodule init
	@git submodule update

README README.md: README.org
	emacs -Q --batch --script readme.el

.PHONY: distclean clean-contrib git-submodules

.include <bsd.prog.mk>
