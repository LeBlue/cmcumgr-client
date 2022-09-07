/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "ptest/ptest.h"

#include "smp_serial.h"

static void test_cli_parse_serial_connstring(void)
{
    int rc;
    const char args[] = {
        "dev=/dev/ttyUSB0,baud=230400",
    };
    char connstring[sizeof(args)];
    memcpy(connstring, args, sizeof(args));

    PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0,baud=230400", connstring);
    struct serial_opts ser_opts;
    rc = parse_serial_connstring(connstring, &ser_opts);
    PT_ASSERT(rc == 0);
    PT_ASSERT(ser_opts.speed == 230400);
    PT_ASSERT(ser_opts.port_name != NULL);
    if (ser_opts.port_name)
        PT_ASSERT_STR_EQ("/dev/ttyUSB0", ser_opts.port_name);
}


static void suite_cli_parse_serial(void)
{
    const char *sn =  "Suite CLI parsing";

    pt_add_test(test_cli_parse_serial_connstring, "Test parsing serial connstring: dev=/dev/ttyUSB0,baud=230400", sn);
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_cli_parse_serial);

    return pt_run();
}
