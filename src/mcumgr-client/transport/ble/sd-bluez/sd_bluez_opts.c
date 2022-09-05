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

enum SMP_SERIAL_OPTION {
    SMP_SERIAL_OPT_DEV = 0,
    SMP_SERIAL_OPT_SPEED,
};

enum SMP_SD_BLUEZ_OPTION {
    SMP_SD_BLUEZ_CHAR_PATH_OPT = 0,
    SMP_SD_BLUEZ_METHOD_OPT = 1,
};

struct transport_option {
    const char *token;
    const char *default_value;
    const char *help;
};

static const struct transport_option smp_sd_bluez_options[] = {
    [SMP_SD_BLUEZ_CHAR_PATH_OPT] = { "charpath", NULL, "bluez characteristic path (/org/bluez/hci0/..." },
    [SMP_SD_BLUEZ_METHOD_OPT] = { "method", "dbus", "characteristic write/notify method, either 'fd' or 'dbus'" },
};

void print_sd_bluez_options(void)
{
    const int padlen = 20;

    for (size_t idx = 0; idx < (sizeof(smp_sd_bluez_options)/sizeof(smp_sd_bluez_options[0])); ++idx) {
        int len = strlen(smp_sd_bluez_options[idx].token);

        if (len >= padlen) len = 0; else len = padlen - len;

        if (smp_sd_bluez_options[idx].default_value) {
            fprintf(stderr, "   %s  %*s%s (%s)\n", smp_sd_bluez_options[idx].token, len, "", smp_sd_bluez_options[idx].help, smp_sd_bluez_options[idx].default_value);
        } else {
            fprintf(stderr, "   %s  %*s%s\n", smp_sd_bluez_options[idx].token, len, "", smp_sd_bluez_options[idx].help);
        }
    }
}


int parse_sd_bluez_connstring(const char* connstring, struct sd_bluez_opts *sdbz_opts)
{
    const char *const token[] = {
        [SMP_SD_BLUEZ_CHAR_PATH_OPT] = smp_sd_bluez_options[SMP_SD_BLUEZ_CHAR_PATH_OPT].token,
        [SMP_SD_BLUEZ_METHOD_OPT] = smp_sd_bluez_options[SMP_SD_BLUEZ_METHOD_OPT].token,
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
            case SMP_SD_BLUEZ_CHAR_PATH_OPT:
                sdbz_opts->mcumgr_char = value;
                break;
            case SMP_SD_BLUEZ_METHOD_OPT:
                if (!strcmp(value, "fd")) {
                    sdbz_opts->method = SD_BLUEZ_METHOD_FD;
                } else if (!strcmp(value, "dbus")) {
                    sdbz_opts->method = SD_BLUEZ_METHOD_DBUS;
                } else {
                    fprintf(stderr, "Suboption '%s' has invalid value '%s'\n", token[SMP_SD_BLUEZ_METHOD_OPT], value);
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
