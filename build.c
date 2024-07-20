/*
  This is a unity build file for aar. The source comes with a BSD
  (bmake) makefile which provides support for tracking changes to
  source files and toggling debug builds. If you do not have bmake
  installed, yyou may easily build aar by compiling this file and
  contrib/aes256/aes256.c.

  The minimum requires to build aar are:

      cc -o aar -D AAR_OS_POSIX build.c contrib/aes256/aes256.c


  Supported macro flags are,

  | MACRO FLAG         | DESCRIPTION                            |
  |--------------------+----------------------------------------|
  | AAR_OS_POSIX       |  Build for a POSIX compliate platform. |
  | _AAR_DEBUG_NOCRYPT |  Don't encrypt and decrypt blocks.     |

 */

#ifdef AAR_OS_POSIX
#define _XOPEN_SOURCE 500
#endif

// libc headers
#include <stdio.h>
#include <stdbool.h>

// third party libs
#include "libs/typeok.h"
#include "libs/base64.h"
#define NSTRINGS_MAIN
#include "libs/nstrings.h"

#define BACK_TO_TABLES // Use pre-calculated tables for AES
#include "contrib/aes256/aes256.h"

// aar application files
#include "aarfmt.h"
#ifdef AAR_OS_POSIX
#include "os_posix.c"
#endif

#include "diskops.c"
#include "main.c"
