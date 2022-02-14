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

void reset_getopt(void)
{
#ifdef __GLIBC__
    optind = 0;
#else
    optind = 1;
#endif
}


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

/**
 * @brief get integer from option arg
 *
 * @param arg  option arg string
 * @param num  where to save parsed integer
 *
 * @return 0 on success, -EINVAL otherwise
 */
static int get_int_optarg(const char *arg, int *num)
{
    const char *numstr = get_optarg(arg);
    if (!numstr) {
        return -EINVAL;
    }
    int ret = scanf("%d", num);
    if (ret == 1) {
        return 0;
    }
    return -EINVAL;
}

#define COMMON_OPTS "ht:"


#define UNRECOGNIZED_OPTION -ENOENT
#define MISSING_ARGUMENT -ENODATA
#define MISSING_COMMAND -ENOMSG
#define ACCESS_ARGUMENTS -E2BIG
/* EINVAL is used for API usage error, this one is invalid cli option argument */
#define INVALID_ARGUMENT -EBADMSG


struct subcmd {
    enum subcommand cmd;
    const char *name;
    int (*optparser)(struct cli_options *);
};

#define SUB_CMD(_name, _subcmd, _parse_fn) \
    { .cmd = _subcmd, .name = _name, .optparser = _parse_fn }



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
        case 't':
        {
            int ret = get_int_optarg(optarg, &copts->timeout);
            if (ret) {
                copts->optopt = optc;
            }
            return ret;
        }
        case '?':
            copts->optopt = optopt;
            return UNRECOGNIZED_OPTION;
        case ':':
            return MISSING_ARGUMENT;
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
    reset_getopt();

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
    return parse_commmon_positional_args(copts, 1);
}

int parse_analyze_opts(struct cli_options *copts)
{
    return parse_commmon_positional_args(copts, 1);
}


int parse_common_options_no_args(struct cli_options *copts)
{
    int ret;

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

static int parse_image_upload_opts(struct cli_options *copts)
{
    int ret;

    if ((ret = parse_commmon_positional_args(copts, 1))) {
        return ret;
    }

    return ret;
}


static const struct subcmd imgcmds[] = {
    SUB_CMD("list", CMD_IMAGE_LIST, parse_common_options_no_args),
    SUB_CMD("analyze", CMD_IMAGE_INFO, parse_analyze_opts),
    SUB_CMD("test", CMD_IMAGE_TEST, parse_image_test_opts),
    SUB_CMD("upload", CMD_IMAGE_UPLOAD, parse_image_upload_opts),
    SUB_CMD("erase", CMD_IMAGE_ERASE, parse_common_options_no_args),
    { 0 }
};

int parse_subcommand_options(const struct subcmd *subs, struct cli_options *copts)
{
    for (const struct subcmd *sc = subs; sc->name; ++sc) {
        if (!strcmp(copts->cmd, sc->name)) {
            copts->subcmd = sc->cmd;
            if (sc->optparser) {
                return sc->optparser(copts);
            }
            return parse_common_options(copts);
        }
    }
    /* found unrecognized command */
    copts->subcmd = CMD_NONE;
    return UNRECOGNIZED_OPTION;
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

        return parse_subcommand_options(imgcmds, copts);

    } else {
        copts->subcmd = CMD_NONE;
        return MISSING_COMMAND;
    }

    return -EINVAL;
}


static const struct subcmd subcmds[] = {
    SUB_CMD("image", CMD_IMAGE, parse_image_opts),
    SUB_CMD("echo", CMD_ECHO, parse_echo_opts),
    SUB_CMD("reset", CMD_RESET, parse_common_options_no_args),
    SUB_CMD("analyze", CMD_IMAGE_INFO, parse_analyze_opts),
    { 0 }
};

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
    copts->prgname = argv[0];
    copts->timeout = 3;

    reset_getopt();

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

        return parse_subcommand_options(subcmds, copts);

    } else {
        copts->argv = NULL;
        /* no command */
        copts->subcmd = CMD_NONE;
        return MISSING_COMMAND;
    }

    return 0;
}
