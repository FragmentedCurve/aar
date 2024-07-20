#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>

#include "libs/typeok.h"
#define NSTRINGS_MAIN
#include "libs/nstrings.h"
#include "libs/base64.h"

#define BACK_TO_TABLES // Use pre-calculated tables for AES
#include "contrib/aes256/aes256.h"

#include "aarfmt.h"

#include "os_posix.c"
#include "diskops.c"
#include "main.c"
