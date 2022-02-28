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

#include "mcumgr-client/smp_sd_bluez.h"
#include "sd_bluez.h"

int parse_sd_bluez_connstring(const char* connstring, struct sd_bluez_opts *sdbz_opts)
{
    enum {
        CHAR_PATH_OPT = 0,
        METHOD_OPT = 1,
    };
    const char *const token[] = {
        [CHAR_PATH_OPT]   = "charpath",
        [METHOD_OPT] = "method",
        NULL
    };

    char *subopts;
    char *value;
    int errfnd = 0;

    subopts = strdup(connstring);
    if (!subopts) {
        return -ENOMEM;
    }

    memset(sdbz_opts, 0, sizeof(*sdbz_opts));

    /* use as default */
    sdbz_opts->method = SD_BLUEZ_METHOD_DBUS;

    while (*subopts != '\0' && !errfnd) {

        switch (getsubopt(&subopts, (char *const *) token, &value)) {
            case CHAR_PATH_OPT:
                sdbz_opts->mcumgr_char = value;
                break;
            case METHOD_OPT:
                if (!strcmp(value, "fd")) {
                    sdbz_opts->method = SD_BLUEZ_METHOD_FD;
                } else if (!strcmp(value, "dbus")) {
                    sdbz_opts->method = SD_BLUEZ_METHOD_DBUS;
                } else {
                    fprintf(stderr, "Suboption '%s' has invalid value '%s'\n", token[METHOD_OPT], value);
                    return -EINVAL;
                }
                break;
            default:
                fprintf(stderr, "No match found for suboption: '%s'\n", value);
                return -EINVAL;
        }
    }

    return 0;
}
