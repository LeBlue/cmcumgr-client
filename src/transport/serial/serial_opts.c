/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


#include "smp_serial.h"

int parse_serial_connstring(const char* connstring, struct serial_opts *ser_opts)
{
    enum {
        DEV_OPT = 0,
        SPEED_OPT,
    };
    const char *const token[] = {
        [DEV_OPT]   = "dev",
        [SPEED_OPT] = "baudrate",
        NULL
    };

    char *subopts;
    char *value;
    int errfnd = 0;
    int speed;
    char *endptr = NULL;

    subopts = connstring;
    while (*subopts != '\0' && !errfnd) {

        switch (getsubopt(&subopts, (char *const *) token, &value)) {
            case DEV_OPT:
                ser_opts->port_name = value;
                break;

            case SPEED_OPT:
                if (value == NULL) {
                    fprintf(stderr, "Missing value for "
                    "suboption '%s'\n", token[SPEED_OPT]);
                    errfnd = 1;
                    continue;
                }

                speed = strtol(value, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Not a number: %s\n", value);
                    return -1;
                }
                ser_opts->speed = speed;
                break;

            default:
                fprintf(stderr, "No match found for suboption: '%s'\n", value);
                errfnd = 1;
                break;
        }
    }
    if (errfnd)
        return -1;

    return 0;
}