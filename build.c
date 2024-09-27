/*
 * Copyright (c) 2024 Paco Pascal <me@pacopascal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


/*
  This is a unity build file for aar. The source comes with a BSD
  (bmake) makefile which provides support for tracking changes to
  source files and toggling debug builds. If you do not have bmake
  installed, you may easily build aar by compiling this file and
  contrib/aes256/aes256.c.

  The minimum requirements to build aar are:

      cc -o aar -D AAR_OS_POSIX build.c


  Supported macro flags are,

  | MACRO FLAG         | DESCRIPTION                                    |
  |--------------------+------------------------------------------------|
  | AAR_OS_POSIX       | Build for a POSIX compliant platform.          |
  | AAR_IOBUF          | Buffer size for IO operations.                 |
  | AAR_DEF_BZERO      | Define macro for bzero instead of strings.h.   |
  | AAR_CRYPT_LIBTOM   | Use libtomcrypt for AES insteadof aes256.      |
  | _AAR_DEBUG_NOCRYPT | Don't encrypt and decrypt blocks.              |
*/


#ifdef AAR_OS_POSIX
#     define _XOPEN_SOURCE 500
#endif

// libc headers
#include <stdio.h>
#include <stdbool.h>

#ifdef AAR_DEF_BZERO
#     define bzero(dest, len) memset((dest), 0, (len))
#else
#     include <strings.h>
#endif

// third party libs
#include "libs/typeok.h"
#include "libs/base64.h"
#define NSTRINGS_MAIN
#include "libs/nstrings.h"

// aar application files
#include "aar.h"

#ifndef AAR_IOBUF
// This should always be aligned with AAR_PADDING
#     define AAR_IOBUF AAR_PADDING(MegaBytes(100))
#endif

#ifdef AAR_CRYPT_LIBTOM
// Ghetto hack to avoid function name conflicts
#    define base64_encode ltc_base64_encode
#    define base64_decode ltc_base64_decode
#    include "tomcrypt.h"
#    undef base64_encode
#    undef base64_decode
#    include "crypt_libtom.c"
#else
#    define BACK_TO_TABLES // Use pre-calculated tables for AES
#    include "contrib/aes256/aes256.h"
#    include "contrib/aes256/aes256.c"
#    include "crypt_aes256.c"
#endif

#ifdef AAR_OS_POSIX
#    include "os_posix.c"
#endif

#include "diskops.c"
#include "main.c"
