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

#include "smp_serial.h"

enum SMP_SERIAL_OPTION {
    SMP_SERIAL_OPT_DEV = 0,
    SMP_SERIAL_OPT_SPEED,
};

struct transport_option {
    const char *token;
    const char *default_value;
    const char *help;
};

static const struct transport_option smp_serial_options[] = {
    [SMP_SERIAL_OPT_DEV]   = { "dev", NULL, "serial port" },
    [SMP_SERIAL_OPT_SPEED] = { "baud", "115200", "serial port baud rate" },
};

void print_serial_options(void)
{
    const int padlen = 20;

    for (size_t idx = 0; idx < (sizeof(smp_serial_options)/sizeof(smp_serial_options[0])); ++idx) {
        int len = strlen(smp_serial_options[idx].token);

        if (len >= padlen) len = 0; else len = padlen - len;

        if (smp_serial_options[idx].default_value) {
            fprintf(stderr, "   %s  %*s%s (%s)\n", smp_serial_options[idx].token, len, "", smp_serial_options[idx].help, smp_serial_options[idx].default_value);
        } else {
            fprintf(stderr, "   %s  %*s%s\n", smp_serial_options[idx].token, len, "", smp_serial_options[idx].help);
        }
    }
}

int parse_serial_connstring(const char* connstring, struct serial_opts *ser_opts)
{
    const char *const token[] = {
        [SMP_SERIAL_OPT_DEV]   = smp_serial_options[SMP_SERIAL_OPT_DEV].token,
        [SMP_SERIAL_OPT_SPEED] = smp_serial_options[SMP_SERIAL_OPT_SPEED].token,
        NULL
    };

    char *subopts;
    char *value;
    int errfnd = 0;
    int speed;
    char *endptr = NULL;

    memset(ser_opts, 0 , sizeof(*ser_opts));
    /* defaults */
    ser_opts->speed = 115200;

    subopts = strdup(connstring);
    if (!subopts) {
        return -ENOMEM;
    }

    while (*subopts != '\0' && !errfnd) {

        switch (getsubopt(&subopts, (char *const *) token, &value)) {
            case SMP_SERIAL_OPT_DEV:
                ser_opts->port_name = value;
                break;

            case SMP_SERIAL_OPT_SPEED:
                if (value == NULL) {
                    fprintf(stderr, "Missing value for "
                    "suboption '%s'\n", token[SMP_SERIAL_OPT_SPEED]);
                    return -EINVAL;
                }

                speed = strtol(value, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Not a number: %s\n", value);
                    return -EINVAL;
                }
                ser_opts->speed = speed;
                break;

            default:
                fprintf(stderr, "No match found for suboption: '%s'\n", value);
                return -EINVAL;
        }
    }

    if (!ser_opts->port_name) {
        fprintf(stderr, "Missing serial option '%s'\n", token[SMP_SERIAL_OPT_DEV]);
        return -ENODATA;
    }

    return 0;
}
