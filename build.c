#ifdef AAR_OS_POSIX
#define _XOPEN_SOURCE 600
#endif

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>

#include "libs/typeok.h"
#include "libs/base64.h"

#define NSTRINGS_MAIN
#include "libs/nstrings.h"

#define BACK_TO_TABLES // Use pre-calculated tables for AES
#include "contrib/aes256/aes256.h"

#include "aarfmt.h"

#ifdef AAR_OS_POSIX
#include "os_posix.c"
#endif

#include "diskops.c"
#include "main.c"
