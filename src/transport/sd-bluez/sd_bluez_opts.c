/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "smp_sd_bluez.h"

int parse_sd_bluez_connstring(const char* connstring, struct sd_bluez_opts *sdbz_opts)
{
    enum {
        CHAR_PATH_OPT = 0,
    };
    const char *const token[] = {
        [CHAR_PATH_OPT]   = "charpath",
        NULL
    };

    char *subopts;
    char *value;
    int errfnd = 0;

    subopts = strdup(connstring);
    if (!subopts) {
        return -ENOMEM;
    }

    while (*subopts != '\0' && !errfnd) {

        switch (getsubopt(&subopts, (char *const *) token, &value)) {
            case CHAR_PATH_OPT:
                sdbz_opts->mcumgr_char = value;
                break;
            default:
                fprintf(stderr, "No match found for suboption: '%s'\n", value);
                return -EINVAL;
        }
    }

    return 0;
}
