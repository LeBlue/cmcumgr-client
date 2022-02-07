/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef __GLIBC__
#define OPTSTR "+:"
#else
#define OPTSTR ":"
#endif

#include "cli_opts.h"
#include "hexlify.h"

#ifdef VERSION
static const char *version = VERSION;
#else
static const char *version = "0.0.0";
#endif

int usage_common(const char *prgname)
{
    fprintf(stderr, "%s %s\n", prgname, version);
    fprintf(stderr, "Usage: %s [options] <cmd> [cmd_options] [cmd_args]\n", prgname);
    return 0;
}

int usage_reset(const char *prgname)
{
    fprintf(stderr, "Usage: %s [options] reset\n", prgname);
    return 0;
}


int print_common_options(const struct cli_options *copts)
{
    fprintf(stderr, "verbose: %d\n", copts->verbose);
    fprintf(stderr, "help: %d\n", copts->help);
    fprintf(stderr, "version: %d\n", copts->version);
    fprintf(stderr, "conntype: %s", copts->conntype ? copts->conntype : "");
    fprintf(stderr, "connstring: %s", copts->connstring ? copts->connstring : "");
    return 0;
}

void print_usage_err(const struct cli_options *copts)
{
    if (copts->optopt) {
        fprintf(stderr, "Unrecognized option: %c\n", copts->optopt);
    }
}

/**
 * @brief strip leading '=' from option arg
 *
 * @param arg option arg string
 *
 * @return string without leading '='
 */
static const char* get_optarg(const char *arg)
{
    if (!arg || arg[0] != '=')
        return arg;
    return (arg + 1);
}

#define COMMON_OPTS "h"


#define UNRECOGNIZED_OPTION -ENOENT
#define MISSING_ARGUMENT -ENODATA
#define MISSING_COMMAND -ENOMSG
#define ACCESS_ARGUMENTS -E2BIG
/* EINVAL is used for API usage error, this one is invalid cli option argument */
#define INVALID_ARGUMENT -EBADMSG


/**
 * @brief Check for common options
 *
 * @param optc        currently returned option by getopt
 * @param copts       cli options to update
 * @param other_opts  current command accepts own/other options
 *
 * @retval      0   recognized option was found
 * @retval -ENOENT  unrecognized option was found
 * @retval -ENODATA missing argument to option
 */
int assign_common_opts(struct cli_options *copts, int optc)
{
    switch (optc) {
        case 'h':
            copts->help = 1;
            return 0;
        case '?':
            copts->optopt = optopt;
            return -ENOENT;
        case ':':
            return -ENODATA;
        default:
            return -EINVAL;
    }
}

/**
 * @brief parse common cli options, like -h flag
 *
 * Use this function if the (sub)command does not use own/other flags
 *
 * @param copts   Where to store parsed options
 * @param posarg  whether to expect additional positional arguments
 *
 * @retval       0 parsing success
 * @retval -EINVAL invalid argument provided
 * @retval -ENOENT unrecognized option or (sub)command or missing required argument
 */
static int parse_common_options(struct cli_options *copts)
{
    int argc = copts->argc;
    char *const *argv = copts->argv;
    int opt;

    opterr = 0;
    optind = 1;

    if (!copts || copts->argc < 1 || !copts->argv) {
        return -EINVAL;
    }

    while ((opt = getopt(argc, argv, OPTSTR COMMON_OPTS)) != -1) {
        int ret = assign_common_opts(copts, opt);
        if (ret) {
            return ret;
        }
    }

    copts->argc = argc - optind;
    if (copts->argc <= 0) {
        copts->argv = NULL;
    } else {
        copts->argv = argv + optind;
    }

    return 0;
}


static int parse_commmon_positional_args(struct cli_options *copts, int nargs)
{
    int ret, argn;

    if (!copts || nargs > CMD_POS_ARGS_MAX) {
        return -EINVAL;
    }

    if ((ret = parse_common_options(copts))) {
        return ret;
    }
    if (copts->help) {
        return 0;
    }

    /* got pos arg */
    for (argn = 0; copts->argc > 0 && argn < nargs; argn++) {
        // copts->cmdopts.os_echo.echo_str = copts->argv[0];
        copts->cmdopts.positional.arg[argn] = copts->argv[0];
        copts->argc--;
        copts->argv++;
        nargs--;
    }
    /* unxpected arg */
    if (copts->argc > 0) {
        return ACCESS_ARGUMENTS;
    } else if (argn < nargs) {
        ret =  MISSING_ARGUMENT;
    }
    copts->argv = NULL;
    return ret;
}


int parse_echo_opts(struct cli_options *copts)
{
    int ret;

    if (!copts || copts->subcmd != CMD_ECHO) {
        return -EINVAL;
    }

    if ((ret = parse_common_options(copts))) {
        return ret;
    }

    /* got echo string */
    if (copts->argc > 0) {
        copts->cmdopts.os_echo.echo_str = copts->argv[0];
        copts->argc--;
        copts->argv++;
    }
    /* unxpected arg */
    if (copts->argc > 0) {
        return ACCESS_ARGUMENTS;
    }
    copts->argv = NULL;
    return 0;
}

int parse_analyze_opts(struct cli_options *copts)
{
    if (!copts || copts->subcmd != CMD_IMAGE_INFO) {
        return -EINVAL;
    }
    int argc = copts->argc;
    char *const *argv = copts->argv;

    int opt;

    opterr = 0;
    optind = 1;

    while ((opt = getopt(argc, argv, OPTSTR "h")) != -1) {
        switch (opt) {
            case 'h':
                copts->help = 1;
                break;
            case '?':
                /* unrecognized option */
                copts->optopt = optopt;
                return UNRECOGNIZED_OPTION;
            case ':':
                /* missing required arg */
                copts->optopt = optopt;
                return MISSING_ARGUMENT;
            default: /* bug: missing case */
                return -EINVAL;
        }
    }

    /* got filename */
    if (argc > optind) {
        copts->cmdopts.analyze.file_name = argv[optind];
    }
    /* unxpected arg */
    if (argc > (optind + 1)) {
        return ACCESS_ARGUMENTS;
    }
    return 0;
}


int parse_reset_opts(struct cli_options *copts)
{
    int ret;

    if (!copts || copts->subcmd != CMD_RESET) {
        return -EINVAL;
    }

    if ((ret = parse_common_options(copts))) {
        return ret;
    }
    if (copts->argc) {
        return ACCESS_ARGUMENTS;
    }

    return 0;
}

static int parse_image_test_opts(struct cli_options *copts)
{
    int ret;

    if ((ret = parse_commmon_positional_args(copts, 1))) {
        return ret;
    }
    if ((strlen(copts->cmdopts.positional.arg[0]) + 1) != IMAGE_HASH_STR_MAX) {
        return INVALID_ARGUMENT;
    }
    copts->cmdopts.img_test.confirm = false;
    return unhexlify(copts->cmdopts.positional.arg[0],
                     copts->cmdopts.img_test.fw_sha,
                     sizeof(copts->cmdopts.img_test.fw_sha));
    if (ret != sizeof(copts->cmdopts.img_test.fw_sha)) {
        return INVALID_ARGUMENT;
    }
    return 0;
}

int parse_image_opts(struct cli_options *copts)
{
    int ret;

    if (!copts || copts->subcmd != CMD_IMAGE) {
        return -EINVAL;
    }
    if ((ret = parse_common_options(copts))) {
        return ret;
    }

    /* abort parsing */
    if (copts->help) {
        return 0;
    }

    /* got command */
    if (copts->argc > 0) {
        copts->cmd = *copts->argv;
        copts->cmdind = optind;
        if (!strcmp("list", copts->cmd)) {
            copts->subcmd = CMD_IMAGE_LIST;
            return parse_common_options(copts);
        } else if (!strcmp("analyze", copts->cmd)) {
            copts->subcmd = CMD_IMAGE_INFO;
            return parse_commmon_positional_args(copts, 1);
        } else if (!strcmp("erase", copts->cmd)) {
            copts->subcmd = CMD_IMAGE_ERASE;
            return parse_common_options(copts);
        } else if (!strcmp("test", copts->cmd)) {
            copts->subcmd = CMD_IMAGE_TEST;
            return parse_image_test_opts(copts);
        } else if (!strcmp("confirm", copts->cmd)) {
            copts->subcmd = CMD_IMAGE_CONFIRM;
            return parse_common_options(copts);
        } else {
            copts->subcmd = CMD_NONE;
            return UNRECOGNIZED_OPTION;
        }
    } else {
        copts->subcmd = CMD_NONE;
        return MISSING_COMMAND;
    }

    return -EINVAL;
}


/**
 * @brief parse cli options
 *
 * @param argc  Argument count
 * @param argv  Arguments
 * @param copts Where to store parsed options
 *
 * @retval       0  parsing success
 * @retval -EINVAL  invalid argument provided (API usage error)
 * @retval -ENOENT  unrecognized option or (sub)command
 * @retval -ENODATA missing option argument.
 * @retval -E2BIG   access argument
 * @retval -ENOMSG  missing required argument
 *
 */
int parse_cli_options(int argc, char *const *argv, struct cli_options *copts)
{
    int opt;

    if (argc < 1 || !argv || !copts) {
        return -EINVAL;
    }

    /* defaults */
    memset(copts, 0, sizeof(*copts));
    copts->conntype = "serial";
    copts->argc = argc;
    copts->argv = argv;
    opterr = 0;
    optind = 1;
    copts->prgname = argv[0];


    while ((opt = getopt(argc, argv, OPTSTR "c:hs:t:vV")) != -1) {
        switch (opt) {
            case 'c':
                copts->connstring = get_optarg(optarg);
                break;
            case 'h':
                copts->help = 1;
                break;
            case 's':
                copts->connstring = get_optarg(optarg);
                break;
            case 't':
                copts->conntype = get_optarg(optarg);
                break;
            case 'v':
                ++copts->verbose;
                break;
            case 'V':
                copts->version = 1;
                break;
            // case '-':
            //     parse_long_opt(argc, argv, copts);
            //     break;
            case '?':
                /* unrecognized option */
                copts->optopt = optopt;
                return UNRECOGNIZED_OPTION;
            case ':':
                /* missing required arg */
                copts->optopt = optopt;
                return MISSING_ARGUMENT;
            default: /* '?' */
                // usage_common(argv[0]);
                return -EINVAL;
        }
    }
    copts->argc = argc - optind;
    copts->argv = argv + optind;

    if (copts->help) {
        return 0;
    }

    /* got command */
    if (copts->argc > 0) {
        copts->cmd = *copts->argv;
        copts->cmdind = optind;
        if (!strcmp("image", copts->cmd)) {
            copts->subcmd = CMD_IMAGE;
            return parse_image_opts(copts);
        } else if (!strcmp("analyze", copts->cmd)) {
            copts->subcmd = CMD_IMAGE_INFO;
            // return parse_analyze_opts(copts);
            return parse_commmon_positional_args(copts, 1);

        } else if (!strcmp("echo", copts->cmd)) {
            copts->subcmd = CMD_ECHO;
            // return parse_echo_opts(copts);
            return parse_commmon_positional_args(copts, 1);
        } else if (!strcmp("reset", copts->cmd)) {
            copts->subcmd = CMD_RESET;
            return parse_common_options(copts);
        } else {
            /* found unrecognized command */
            copts->subcmd = CMD_NONE;
            return UNRECOGNIZED_OPTION;
        }
    } else {
        copts->argv = NULL;
        /* no command */
        copts->subcmd = CMD_NONE;
        return MISSING_COMMAND;
    }

    return 0;
}


