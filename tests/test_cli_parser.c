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
#include "utils_test.h"

#include "cli_opts.h"

/* copy args to avoid compiler warnings (argv strings cannot be const) */
static char **build_options(int argc, const char **argv)
{
    size_t sz, sz_left;
    int i;
    for (i = 0, sz = 0; i < argc; ++i) {
        sz += strlen(argv[i]);
        ++sz;
    }
    sz_left = sz;
    sz += (argc * sizeof(char*));
    char **argv_new = calloc(sz, 1);

    assert(argv_new);

    char *args = (char*)(argv_new + argc);

    for (i = 0; i < argc; ++i) {
        argv_new[i] = args;
        strncpy(args, argv[i], sz_left);
        size_t len = strlen(args) + 1;
        sz_left -= len;
        args += len;
    }
    return argv_new;
}

static void check_shuffle(int argc, char **argv, const char **args)
{
    int i;
    for (i=0; i < argc; ++i)
    {
        PT_ASSERT_STR_EQ(argv[i], args[i]);
    }
}


/**
 * @brief Test -h option
 *
 */
static void test_cli_parse_common_help(void)
{
    int argc = 2;
    const char *args[] = {
        "mcumgr",
        "-h",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test long --help option
 *
 */
static void test_cli_parse_common_help_long(void)
{
    int argc = 2;
    const char *args[] = {
        "mcumgr",
        "--help",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test unknown option
 *
 */
static void test_cli_parse_common_unknown(void)
{
    int argc = 2;
    const char *args[] = {
        "mcumgr",
        "-k",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOENT);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);
    PT_ASSERT(copts.optopt == 'k');

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test unknown option
 *
 */
static void test_cli_parse_common_unknown_long(void)
{
    int argc = 2;
    const char *args[] = {
        "mcumgr",
        "--kv",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOENT);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);
    PT_ASSERT(copts.optopt == 0);
    PT_ASSERT(copts.argv[0] != NULL);
    if (copts.argv[0])
        PT_ASSERT_STR_EQ(copts.argv[0], "--kv");

    check_shuffle(argc, argv, args);

    free(argv);
}



/**
 * @brief Test -v option
 *
 */
static void test_cli_parse_common_verbose_1(void)
{
    int argc = 2;
    const char *args[] = {
        "mcumgr",
        "-v",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}


/**
 * @brief Test -v -v option
 *
 */
static void test_cli_parse_common_verbose_2(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test -v -v option
 *
 */
static void test_cli_parse_common_verbose_3(void)
{
    int argc = 2;
    const char *args[] = {
        "mcumgr",
        "-vv",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */

    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}


/**
 * @brief Test -v -v -h -V option
 *
 */
static void test_cli_parse_common_all(void)
{
    int argc = 5;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "-h",
        "-V",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    // PT_ASSERT(rc == -ENOMSG); /* missing commmand */
    PT_ASSERT(rc == 0); /* -h ignores miising command */

    PT_ASSERT(copts.version == 1);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test -s=dev=/dev/ttyUSB0 option
 *
 */
static void test_cli_parse_common_connstring(void)
{
    int argc = 5;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "-s", "dev=/dev/ttyUSB0"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);
    PT_ASSERT_STR_EQ(args[4], copts.connstring);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test -sdev=/dev/ttyUSB0 option
 *
 */
static void test_cli_parse_common_connstring_2(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "-sdev=/dev/ttyUSB0"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */

    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);
    PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0", copts.connstring);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test -s=dev=/dev/ttyUSB0 option
 *
 */
static void test_cli_parse_common_connstring_3(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "-s=dev=/dev/ttyUSB0"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);
    PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0", copts.connstring);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test --connstring=dev=/dev/ttyUSB0 option
 *
 */
static void test_cli_parse_common_connstring_4(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "--connstring=dev=/dev/ttyUSB0"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);
    PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0", copts.connstring);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test --connstring dev=/dev/ttyUSB0 option
 *
 */
static void test_cli_parse_common_connstring_5(void)
{
    int argc = 5;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "--connstring", "dev=/dev/ttyUSB0"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* missing commmand */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == NULL);
    PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0", copts.connstring);

    check_shuffle(argc, argv, args);

    free(argv);
}


/**
 * @brief Test cmd arg
 *
 */
static void test_cli_parse_common_cmd(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "reset",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[3]);

    if (copts.cmd)
        PT_ASSERT_STR_EQ("reset", copts.cmd);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test cmd arg with arg
 *
 */
static void test_cli_parse_common_cmd_w_arg(void)
{
    int argc = 5;
    const char *args[] = {
        "mcumgr",
        "-v",
        "-v",
        "reset",
        "-v", /* should not be counted */
    };
    char **argv = build_options(argc, args);

    struct cli_options copts;
    optind = 0;
    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOENT);
    PT_ASSERT(copts.optopt == 'v');

    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 2);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[3]);
    PT_ASSERT(copts.subcmd == CMD_RESET);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("reset", copts.cmd);


    check_shuffle(argc, argv, args);

    free(argv);
}

static void test_cli_parse_common_einval_1(void)
{
    int argc = 0;
    const char *args[] = { "mcumgr" };
    struct cli_options copts;
    char **argv = build_options(1, args);

    int rc = parse_cli_options(argc, argv, &copts);
    PT_ASSERT(rc == -EINVAL);
}


static void test_cli_parse_common_einval_2(void)
{
    int argc = 1;
    struct cli_options copts;
    int rc = parse_cli_options(argc, NULL, &copts);
    PT_ASSERT(rc == -EINVAL);
}


static void test_cli_parse_common_einval_3(void)
{
    int argc = 1;
    const char *args[] = { "mcumgr" };
    char **argv = build_options(argc, args);

    int rc = parse_cli_options(argc, argv, NULL);
    PT_ASSERT(rc == -EINVAL);
}

static void test_cli_parse_common_missing_optarg_c(void)
{
    int argc = 2;
    const char *args[] = { "mcumgr", "-s" };
    char **argv = build_options(argc, args);
    struct cli_options copts;

    int rc = parse_cli_options(argc, argv, &copts);
    PT_ASSERT(rc == -ENODATA);
}


static void test_cli_parse_common_missing_optarg_t(void)
{
    int argc = 2;
    const char *args[] = { "mcumgr", "-t" };
    char **argv = build_options(argc, args);
    struct cli_options copts;

    int rc = parse_cli_options(argc, argv, &copts);
    PT_ASSERT(rc == -ENODATA);
}


static void test_cli_parse_common_missing_optarg_s(void)
{
    int argc = 2;
    const char *args[] = { "mcumgr", "-s" };
    char **argv = build_options(argc, args);
    struct cli_options copts;

    int rc = parse_cli_options(argc, argv, &copts);
    PT_ASSERT(rc == -ENODATA);
}


static void test_cli_parse_common_missing_arg(void)
{
    int argc = 1;
    const char *args[] = { "mcumgr" };
    char **argv = build_options(argc, args);
    struct cli_options copts;

    int rc = parse_cli_options(argc, argv, &copts);
    /* TODO: return -ENODATA?*/
    PT_ASSERT(rc == -ENOMSG);
    // PT_ASSERT(rc == 0);
}

static void test_cli_parse_common_unrecognized_option(void)
{
    int argc = 3;
    const char *args[] = { "mcumgr", "-x", "reset" };
    char **argv = build_options(argc, args);
    struct cli_options copts;

    int rc = parse_cli_options(argc, argv, &copts);
    PT_ASSERT(rc == -ENOENT);
}

static void test_cli_parse_common_unrecognized_command(void)
{
    int argc = 2;
    const char *args[] = { "mcumgr", "foobar" };
    char **argv = build_options(argc, args);
    struct cli_options copts;

    int rc = parse_cli_options(argc, argv, &copts);
    PT_ASSERT(rc == -ENOENT);
}


static void suite_cli_parse_common(void)
{
    const char *sn =  "Suite CLI parsing";

    pt_add_test(test_cli_parse_common_help, "Test parsing common CLI options: -h", sn);
    pt_add_test(test_cli_parse_common_help_long, "Test parsing common CLI options: --help", sn);
    pt_add_test(test_cli_parse_common_unknown, "Test parsing common CLI options: -k unknown", sn);
    pt_add_test(test_cli_parse_common_unknown_long, "Test parsing common CLI options: --kv", sn);
    pt_add_test(test_cli_parse_common_verbose_1, "Test parsing common CLI options: -v", sn);
    pt_add_test(test_cli_parse_common_verbose_2, "Test parsing common CLI options: -v -v", sn);
    pt_add_test(test_cli_parse_common_verbose_3, "Test parsing common CLI options: -vv", sn);
    pt_add_test(test_cli_parse_common_all, "Test parsing common CLI options: -v -v -h -V", sn);
    pt_add_test(test_cli_parse_common_connstring, "Test parsing common CLI options: -s dev=/dev/ttyUSB0", sn);
    pt_add_test(test_cli_parse_common_connstring_2, "Test parsing common CLI options: -sdev=/dev/ttyUSB0", sn);
    pt_add_test(test_cli_parse_common_connstring_3, "Test parsing common CLI options: -s=dev=/dev/ttyUSB0", sn);
    pt_add_test(test_cli_parse_common_connstring_4, "Test parsing common CLI options: --connstring=dev=/dev/ttyUSB0", sn);
    pt_add_test(test_cli_parse_common_connstring_5, "Test parsing common CLI options: --connstring dev=/dev/ttyUSB0", sn);
    pt_add_test(test_cli_parse_common_cmd, "Test parsing common CLI options: -v -v reset", sn);
    pt_add_test(test_cli_parse_common_cmd_w_arg, "Test parsing common CLI options: -v -v reset -v", sn);

    pt_add_test(test_cli_parse_common_einval_1, "Test parsing common CLI options: arg 1: EINVAL", sn);
    pt_add_test(test_cli_parse_common_einval_2, "Test parsing common CLI options: arg 2: EINVAL", sn);
    pt_add_test(test_cli_parse_common_einval_3, "Test parsing common CLI options: arg 3: EINVAL", sn);
    pt_add_test(test_cli_parse_common_missing_optarg_c, "Test parsing common CLI options: missing optarg: -c", sn);
    pt_add_test(test_cli_parse_common_missing_optarg_s, "Test parsing common CLI options: missing optarg: -s", sn);
    pt_add_test(test_cli_parse_common_missing_optarg_t, "Test parsing common CLI options: missing optarg: -t", sn);
    pt_add_test(test_cli_parse_common_missing_arg, "Test parsing common CLI options: missing argument", sn);
    pt_add_test(test_cli_parse_common_unrecognized_option, "Test parsing common CLI options: unrecognized option", sn);
    pt_add_test(test_cli_parse_common_unrecognized_command, "Test parsing common CLI options: unrecognized command", sn);


}


/**
 * @brief Test echo cmd arg with arg
 *
 */
static void test_cli_parse_full_echo_cmd_w_arg(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "echo",
        "Hallo",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str != NULL);
        if (copts.cmdopts.os_echo.echo_str)
            PT_ASSERT_STR_EQ("Hallo", copts.cmdopts.os_echo.echo_str);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}

/**
 * @brief Test echo cmd arg with connstring
 *
 */
static void test_cli_parse_full_echo_cmd_w_connstring(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-s=dev=/dev/ttyUSB0,baud=230400",
        "echo",
        "Hallo",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};
    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);
    PT_ASSERT(copts.connstring != NULL);
    check_shuffle(argc, argv, args);

    if (copts.connstring) {
        PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0,baud=230400", copts.connstring);
    }

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str != NULL);
        if (copts.cmdopts.os_echo.echo_str)
            PT_ASSERT_STR_EQ("Hallo", copts.cmdopts.os_echo.echo_str);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}


/**
 * @brief Test echo cmd arg with connstring longopt with equal
 *
 */
static void test_cli_parse_full_echo_cmd_w_connstring_long(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "--connstring=dev=/dev/ttyUSB0,baud=230400",
        "echo",
        "Hallo",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};
    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);
    PT_ASSERT(copts.connstring != NULL);
    check_shuffle(argc, argv, args);

    if (copts.connstring) {
        PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0,baud=230400", copts.connstring);
    }

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str != NULL);
        if (copts.cmdopts.os_echo.echo_str)
            PT_ASSERT_STR_EQ("Hallo", copts.cmdopts.os_echo.echo_str);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}


/**
 * @brief Test echo cmd arg with connstring longopt with 2 args
 *
 */
static void test_cli_parse_full_echo_cmd_w_connstring_long_alt(void)
{
    int argc = 5;
    const char *args[] = {
        "mcumgr",
        "--connstring", "dev=/dev/ttyUSB0,baud=230400",
        "echo",
        "Hallo",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};
    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[3]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);
    PT_ASSERT(copts.connstring != NULL);
    check_shuffle(argc, argv, args);

    if (copts.connstring) {
        PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0,baud=230400", copts.connstring);
    }

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str != NULL);
        if (copts.cmdopts.os_echo.echo_str)
            PT_ASSERT_STR_EQ("Hallo", copts.cmdopts.os_echo.echo_str);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}


/**
 * @brief Test echo cmd arg with arg
 *
 */
static void test_cli_parse_echo_cmd_help(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "echo",
        "-h",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str == NULL);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}

/**
 * @brief Test echo cmd help
 *
 */
static void test_cli_parse_echo_cmd_help_long(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "echo",
        "--help",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str == NULL);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}


/**
 * @brief Test echo cmd arg with arg
 *
 */
static void test_cli_parse_echo_cmd_w_access_arg(void)
{
    int argc = 5;
    const char *args[] = {
        "mcumgr",
        "-v",
        "echo",
        "Hallo",
        "access"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -E2BIG);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    /* one access arg, rest consumed */
    PT_ASSERT(copts.argc == 1);
    PT_ASSERT(copts.argv[0] == argv[4]);

    check_shuffle(argc, argv, args);

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str != NULL);
        if (copts.cmdopts.os_echo.echo_str)
            PT_ASSERT_STR_EQ("Hallo", copts.cmdopts.os_echo.echo_str);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}


/**
 * @brief Test echo cmd arg with arg
 *
 */
static void test_cli_parse_echo_cmd_w_missing_arg(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "-v",
        "echo"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENODATA);
    PT_ASSERT(copts.optopt == 0); /* not a option argumetn missing */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_ECHO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("echo", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    if (copts.subcmd == CMD_ECHO) {
        PT_ASSERT(copts.cmdopts.os_echo.echo_str == NULL);

        check_shuffle(argc, argv, args);
    }

    free(argv);
}




static void suite_cli_parse_echo(void)
{
    const char *sn = "Suite CLI parsing echo";

    pt_add_test(test_cli_parse_full_echo_cmd_w_arg, "Test parsing OS echo CLI options full: mcumgr -v echo Hallo", sn);
    pt_add_test(test_cli_parse_full_echo_cmd_w_connstring, "Test parsing OS echo CLI options full: mcumgr -s... -v echo Hallo", sn);
    pt_add_test(test_cli_parse_full_echo_cmd_w_connstring_long, "Test parsing OS echo CLI options full: mcumgr --connstring ... -v echo Hallo", sn);
    pt_add_test(test_cli_parse_full_echo_cmd_w_connstring_long_alt, "Test parsing OS echo CLI options full: mcumgr --connstring=... -v echo Hallo", sn);
    pt_add_test(test_cli_parse_echo_cmd_help, "Test parsing OS echo common CLI options: help: mcumgr -v echo -h", sn);
    pt_add_test(test_cli_parse_echo_cmd_help_long, "Test parsing OS echo common CLI options: help: mcumgr -v echo --help", sn);


    pt_add_test(test_cli_parse_echo_cmd_w_access_arg, "Test parsing OS echo common CLI options: Access arg: mcumgr -v echo Hallo access", sn);
    pt_add_test(test_cli_parse_echo_cmd_w_missing_arg, "Test parsing OS echo common CLI options: Missing arg: mcumgr -v echo", sn);


}


/**
 * @brief Test reset cmd arg with arg
 *
 */
static void test_cli_parse_full_reset_cmd(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "-v",
        "reset",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_RESET);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("reset", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test reset cmd arg with connstring
 *
 */
static void test_cli_parse_full_reset_cmd_w_connstring(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "-s=dev=/dev/ttyUSB0,baud=230400",
        "reset",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};
    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_RESET);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("reset", copts.cmd);

    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);
    PT_ASSERT(copts.connstring != NULL);
    check_shuffle(argc, argv, args);

    if (copts.connstring) {
        PT_ASSERT_STR_EQ("dev=/dev/ttyUSB0,baud=230400", copts.connstring);
    }

    free(argv);
}

/**
 * @brief Test reset cmd arg with -h arg
 *
 */
static void test_cli_parse_full_reset_cmd_help(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "reset",
        "-h",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_RESET);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("reset", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test reset cmd arg with --help arg
 *
 */
static void test_cli_parse_full_reset_cmd_help_long(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "reset",
        "--help",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[1]);
    PT_ASSERT(copts.subcmd == CMD_RESET);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("reset", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}


/**
 * @brief Test reset cmd arg with access arg
 *
 */
static void test_cli_parse_full_reset_cmd_w_access_arg(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "reset",
        "access"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -E2BIG);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_RESET);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("reset", copts.cmd);

    /* one access arg, rest consumed */
    PT_ASSERT(copts.argc == 1);
    PT_ASSERT(copts.argv[0] == argv[3]);

    check_shuffle(argc, argv, args);

    free(argv);
}


static void suite_cli_parse_reset(void)
{
    const char *sn = "Suite CLI parsing reset";

    pt_add_test(test_cli_parse_full_reset_cmd, "Test parsing OS reset CLI options: mcumgr -v reset", sn);
    pt_add_test(test_cli_parse_full_reset_cmd_w_connstring, "Test parsing OS reset CLI options: mcumgr -c... -v reset", sn);
    pt_add_test(test_cli_parse_full_reset_cmd_help, "Test parsing OS reset CLI options: help: mcumgr -v reset -h", sn);
    pt_add_test(test_cli_parse_full_reset_cmd_help_long, "Test parsing OS reset CLI options: help: mcumgr reset --help", sn);


    pt_add_test(test_cli_parse_full_reset_cmd_w_access_arg, "Test parsing OS reset CLI options: Access arg: mcumgr -v reset access", sn);
}


/**
 * @brief Test analyze cmd arg with filename arg
 *
 */
static void test_cli_parse_analyze(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "analyze",
        "some_file.bin",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};
    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[1]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_INFO);
    if (copts.cmd) {
        PT_ASSERT_STR_EQ("analyze", copts.cmd);
    }

    /* all args consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd == argv[1]);
    PT_ASSERT(copts.cmdopts.analyze.file_name != NULL);
    if (copts.cmdopts.analyze.file_name) {
        PT_ASSERT_STR_EQ("some_file.bin", copts.cmdopts.analyze.file_name);
    }

    free(argv);
}

/**
 * @brief Test analyze cmd arg with --help
 *
 */
static void test_cli_parse_analyze_cmd_help_long(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "analyze",
        "--help",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[1]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_INFO);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("analyze", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}


static void suite_cli_parse_analyze(void)
{
    const char *sn = "Suite CLI parsing analyze";
    pt_add_test(test_cli_parse_analyze, "Test parsing analyze CLI options: analyze some_file.bin", sn);
    pt_add_test(test_cli_parse_analyze_cmd_help_long, "Test parsing analyze CLI options: analyze --help", sn);
}



/**
 * @brief Test image cmd arg with arg
 *
 */
static void test_cli_parse_full_image_cmd(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "-v",
        "image",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOMSG); /* -ENOENT ? */
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("image", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test image cmd arg with -h arg
 *
 */
static void test_cli_parse_full_image_cmd_help(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "image",
        "-h",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("image", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test image cmd arg with --help
 *
 */
static void test_cli_parse_full_image_cmd_help_long(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "image",
        "--help",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[1]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("image", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}


/**
 * @brief Test image cmd arg with unkown subcommand arg
 *
 */
static void test_cli_parse_full_image_cmd_w_access_arg(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "-v",
        "image",
        "access"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == -ENOENT);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 1);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("image", copts.cmd);

    /* one access arg, rest consumed */
    PT_ASSERT(copts.argc == 1);
    PT_ASSERT(copts.argv[0] == argv[3]);

    check_shuffle(argc, argv, args);

    free(argv);
}


static void suite_cli_parse_image(void)
{
    const char *sn = "Suite CLI parsing image";

    pt_add_test(test_cli_parse_full_image_cmd, "Test parsing OS image CLI options: mcumgr -v image", sn);
    pt_add_test(test_cli_parse_full_image_cmd_help, "Test parsing OS image CLI options: help: mcumgr -v image -h", sn);
    pt_add_test(test_cli_parse_full_image_cmd_help_long, "Test parsing OS image CLI options: help: mcumgr image --help", sn);

    pt_add_test(test_cli_parse_full_image_cmd_w_access_arg, "Test parsing OS image CLI options: Access arg: mcumgr -v image access", sn);
}



/**
 * @brief Test image list cmd arg with arg
 *
 */
static void test_cli_parse_image_list_cmd(void)
{
    int argc = 3;
    const char *args[] = {
        "mcumgr",
        "image",
        "list"
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_LIST);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("list", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test image list cmd arg with -h arg
 *
 */
static void test_cli_parse_image_list_cmd_help(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "image",
        "list",
        "-h",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_LIST);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("list", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test image list cmd arg with --help
 *
 */
static void test_cli_parse_image_list_cmd_help_long(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "image",
        "list",
        "--help",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_LIST);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("list", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

static void suite_cli_parse_image_list(void)
{
    const char *sn = "Suite CLI parsing image list";

    pt_add_test(test_cli_parse_image_list_cmd, "Test parsing OS image list CLI options: mcumgr image list", sn);
    pt_add_test(test_cli_parse_image_list_cmd_help, "Test parsing OS image list CLI options: help: mcumgr image list -h", sn);
    pt_add_test(test_cli_parse_image_list_cmd_help_long, "Test parsing OS image list CLI options: help: mcumgr image list --help", sn);
}

static const uint8_t hash[32] = "\xac\x35\x2c\x1f\x56\xad\xcb\x10\x29\x2d\xa6\xe1\xbe\x6d\x86\x72"
                                "\xac\xaa\x7b\x34\x32\x3a\x33\xb3\x5b\xdb\xa9\xaa\x25\x83\xc6\xe0";

/**
 * @brief Test image cmd arg with arg
 *
 */
static void test_cli_parse_image_test_cmd(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "image",
        "test",
        "ac352c1f56adcb10292da6e1be6d8672"
        "acaa7b34323a33b35bdba9aa2583c6e0",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 0);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_TEST);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("test", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);
    PT_ASSERT_MEM_EQ(copts.cmdopts.img_test.fw_sha, hash, sizeof(hash));

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test image test cmd arg with -h arg
 *
 */
static void test_cli_parse_image_test_cmd_help(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "image",
        "test",
        "-h",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_TEST);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("test", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

/**
 * @brief Test image test cmd arg with --help
 *
 */
static void test_cli_parse_image_test_cmd_help_long(void)
{
    int argc = 4;
    const char *args[] = {
        "mcumgr",
        "image",
        "test",
        "--help",
    };
    char **argv = build_options(argc, args);

    struct cli_options copts = {0};

    optind = 0;

    int rc = parse_cli_options(argc, argv, &copts);

    PT_ASSERT(rc == 0);
    PT_ASSERT(copts.version == 0);
    PT_ASSERT(copts.verbose == 0);
    PT_ASSERT(copts.help == 1);
    PT_ASSERT(copts.cmd != NULL);
    PT_ASSERT(copts.cmd == argv[2]);
    PT_ASSERT(copts.subcmd == CMD_IMAGE_TEST);
    if (copts.cmd)
        PT_ASSERT_STR_EQ("test", copts.cmd);

    /* everything consumed */
    PT_ASSERT(copts.argc == 0);
    PT_ASSERT(copts.argv == NULL);

    check_shuffle(argc, argv, args);

    free(argv);
}

static void suite_cli_parse_image_test(void)
{
    const char *sn = "Suite CLI parsing image test";

    pt_add_test(test_cli_parse_image_test_cmd, "Test parsing OS image test CLI options: mcumgr image test", sn);
    pt_add_test(test_cli_parse_image_test_cmd_help, "Test parsing OS image test CLI options: help: mcumgr image test -h", sn);
    pt_add_test(test_cli_parse_image_test_cmd_help_long, "Test parsing OS image test CLI options: help: mcumgr image test --help", sn);
}



int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_cli_parse_common);
    pt_add_suite(suite_cli_parse_echo);
    pt_add_suite(suite_cli_parse_reset);
    pt_add_suite(suite_cli_parse_image);
    pt_add_suite(suite_cli_parse_image_list);
    pt_add_suite(suite_cli_parse_image_test);
    pt_add_suite(suite_cli_parse_analyze);

    return pt_run();
}
