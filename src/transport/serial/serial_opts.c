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

int parse_serial_connstring(const char* connstring, struct serial_opts *ser_opts)
{
    enum {
        DEV_OPT = 0,
        SPEED_OPT,
    };
    const char *const token[] = {
        [DEV_OPT]   = "dev",
        [SPEED_OPT] = "baud",
        NULL
    };

    char *subopts;
    char *value;
    int errfnd = 0;
    int speed;
    char *endptr = NULL;

    subopts = strdup(connstring);
    if (!subopts) {
        return -ENOMEM;
    }

    while (*subopts != '\0' && !errfnd) {

        switch (getsubopt(&subopts, (char *const *) token, &value)) {
            case DEV_OPT:
                ser_opts->port_name = value;
                break;

            case SPEED_OPT:
                if (value == NULL) {
                    fprintf(stderr, "Missing value for "
                    "suboption '%s'\n", token[SPEED_OPT]);
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

    return 0;
}
