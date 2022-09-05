/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include "cli_opts.h"
#include "hexlify.h"

#include "mcuboot_img.h"

#ifdef __GLIBC__
#define OPTSTR "+:"
#else
#define OPTSTR ":"
#endif

#ifdef VERSION
static const char *version = VERSION;
#else
static const char *version = "0.0.0";
#endif

static void reset_getopt(void)
{
#ifdef __GLIBC__
    optind = 0;
#else
    optind = 1;
#endif
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
    int ret = sscanf(numstr, "%d", num);
    if (ret == 1) {
        return 0;
    }
    return CLI_INVALID_ARGUMENT;
}

struct longopt {
    const char *name;
    const char *description;
    int opt;
    int arg_num;
};

#define OPT_DEF(_name, _opt, _nargs, _description) \
    { .name = _name, .opt = _opt, .arg_num = _nargs, .description = _description }

#define OPT_DEF_END {0}


struct subcmd {
    enum subcommand cmd;
    const char *name;
    int (*optparser)(struct cli_options *);
    const char *description;
    const struct subcmd *subcmds;
    const struct longopt* lopts;
    const char *args_usage;
};


#define CMD_DEF_FULL(_name, _subcmd, _parse_fn, _lopts, _description, _subcmds, _args_usage) \
    { .cmd = _subcmd, .name = _name, .optparser = _parse_fn, .description = _description, .lopts = _lopts, .subcmds = _subcmds, .args_usage = _args_usage }

#define CMD_DEF_SUB(_name, _subcmd, _parse_fn, _lopts, _description, _subcmds) \
    CMD_DEF_FULL(_name, _subcmd, _parse_fn, _lopts, _description, _subcmds, NULL)

#define CMD_DEF(_name, _subcmd, _parse_fn, _description) \
    CMD_DEF_FULL(_name, _subcmd, _parse_fn, NULL, _description, NULL, NULL)

#define CMD_DEF_ARGS(_name, _subcmd, _parse_fn, _description, _args_usage) \
    CMD_DEF_FULL(_name, _subcmd, _parse_fn, NULL, _description, NULL, _args_usage)

#define CMD_DEF_OPTS(_name, _subcmd, _parse_fn, _lopts, _description) \
    CMD_DEF_FULL(_name, _subcmd, _parse_fn, _lopts, _description, NULL, NULL)


#define CMD_DEF_END {0}


static const struct longopt *find_long_opt(const struct longopt *lopts, const char *loptstr)
{
    if (!loptstr) {
        return NULL;
    }
    for (const struct longopt *lo = lopts; lo->name; ++lo ) {
        size_t len = strlen(lo->name);
        if (!strncmp(loptstr, lo->name, len) &&
            (loptstr[len] == '\0' || loptstr[len] == '=')) {
            return lo;
        }
    }
    return NULL;
}

/* TODO: fix fn arguments */
static const char* get_long_optarg(const struct longopt *lo, int argc, char *const *argv, const char *arg)
{
    size_t flag_len = strlen(lo->name);
    char next = arg[flag_len];
    const char *retarg = NULL;
    if (next == '\0' && optind < argc) {
        retarg = argv[optind];
        optind++;
    } else if (next == '=') {
        retarg = arg + flag_len;
    }

    return retarg;
}


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
            return CLI_UNRECOGNIZED_OPTION;
        case ':':
            return CLI_MISSING_ARGUMENT;
        default:
            return -EINVAL;
    }
}

#define COMMON_OPTS "h-:"

static struct longopt common_longopts[] = {
    OPT_DEF("help", 'h', 0, "Print this help and exit"),
    OPT_DEF_END
};

/**
 * @brief parse common cli options, like -h flag
 *
 * Use this function if the (sub)command does not use own/other flags
 *
 * @param copts   Where to store parsed options
 * @param posarg  whether to expect additional positional arguments
 *
 * @retval        0 parsing success
 * @retval  -EINVAL invalid argument provided
 * @retval  -ENOENT unrecognized option or (sub)command
 * @retval -ENODATA Missing required (option) argument
 * @retval   -E2BIG Unrecognized additional arguments
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
        int ret;
        const char *arg = optarg;
        if (opt == '-') {
            /* arg contains long option without -- */
            const struct longopt *lo = find_long_opt(common_longopts, arg);

            if (!lo) {
                copts->argc = argc - (optind - 1);
                copts->argv += (optind - 1);
                return CLI_UNRECOGNIZED_OPTION;
            }
            opt = lo->opt;
            if (lo->arg_num) {
                arg = get_long_optarg(lo, argc, argv, arg);
                if (!arg) {
                    copts->argc = argc - optind;
                    copts->argv += optind;
                    return CLI_MISSING_ARGUMENT;
                }
            }
        }

        ret = assign_common_opts(copts, opt);
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
        return CLI_ACCESS_ARGUMENTS;
    } else if (argn < nargs) {
        ret = CLI_MISSING_ARGUMENT;
    }
    copts->argv = NULL;
    return ret;
}


static int parse_echo_opts(struct cli_options *copts)
{
    return parse_commmon_positional_args(copts, 1);
}

static int parse_analyze_opts(struct cli_options *copts)
{
    return parse_commmon_positional_args(copts, 1);
}


static int parse_common_options_no_args(struct cli_options *copts)
{
    int ret;

    if ((ret = parse_common_options(copts))) {
        return ret;
    }
    if (copts->argc) {
        return CLI_ACCESS_ARGUMENTS;
    }

    return 0;
}

static int parse_image_test_opts(struct cli_options *copts)
{
    int ret;

    if ((ret = parse_commmon_positional_args(copts, 1))) {
        return ret;
    }

    if (!copts->cmdopts.positional.arg[0]) {
        return ret;
    }

    if ((strlen(copts->cmdopts.positional.arg[0]) + 1) != IMAGE_HASH_STR_MAX) {
        return CLI_INVALID_ARGUMENT;
    }
    copts->cmdopts.img_test.confirm = false;
    ret = unhexlify(copts->cmdopts.positional.arg[0],
                    copts->cmdopts.img_test.fw_sha,
                    sizeof(copts->cmdopts.img_test.fw_sha));
    if (ret != sizeof(copts->cmdopts.img_test.fw_sha)) {
        return CLI_INVALID_ARGUMENT;
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
    CMD_DEF_ARGS("analyze", CMD_IMAGE_INFO, parse_analyze_opts, "Verify and print information of a firmware image file", "FILE"),
    CMD_DEF("list", CMD_IMAGE_LIST, parse_common_options_no_args, "List firmware images on a device"),
    CMD_DEF_ARGS("upload", CMD_IMAGE_UPLOAD, parse_image_upload_opts, "Upload a firmware file", "FILE"),
    CMD_DEF_ARGS("test", CMD_IMAGE_TEST, parse_image_test_opts, "Mark an image to be tested on the next boot", "HASH"),
    CMD_DEF("confirm", CMD_IMAGE_CONFIRM, parse_common_options_no_args, "Confirm a booted slot"),
    CMD_DEF("erase", CMD_IMAGE_ERASE, parse_common_options_no_args, "Erase a slot"),
    CMD_DEF_END
};

static int parse_subcommand_options(const struct subcmd *subs, struct cli_options *copts)
{
    for (const struct subcmd *sc = subs; sc->name; ++sc) {
        if (!strcmp(copts->argv[0], sc->name)) {
            copts->subcmd = sc->cmd;
            copts->cmd = copts->argv[0];
            if (sc->optparser) {
                return sc->optparser(copts);
            }
            return parse_common_options(copts);
        }
    }
    /* found unrecognized command */
    return CLI_UNRECOGNIZED_OPTION;
}

static int parse_image_opts(struct cli_options *copts)
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

    /* got no command */
    if (copts->argc <= 0) {
        return CLI_MISSING_COMMAND;
    }
    return parse_subcommand_options(imgcmds, copts);
}


static const struct subcmd subcmds[] = {
    CMD_DEF_SUB("image", CMD_IMAGE, parse_image_opts, NULL, "Manage firmware on a device", imgcmds),
    CMD_DEF_ARGS("echo", CMD_ECHO, parse_echo_opts, "Send a text string to a device and print the response", "TEXT"),
    CMD_DEF("reset", CMD_RESET, parse_common_options_no_args, "Reset a device"),
    CMD_DEF_ARGS("analyze", CMD_IMAGE_INFO, parse_analyze_opts, "Verify and print information of a firmware image file", "FILE"),
    CMD_DEF_END
};


static struct longopt cli_longopts[] = {
    OPT_DEF("help", 'h', 0, "Print this help and exit"),
    OPT_DEF("version", 'V', 0, "Print version and exit"),
    OPT_DEF("verbose", 'v', 0, "Increase verbosity, can be given multiple times"),
    OPT_DEF("conntype", 1, 1, "Connection type string"),
    OPT_DEF("connstring", 's', 1, "Connection options, comma separated of 'key=value' or 'flag'"),
    OPT_DEF("timeout", 't', 1, "Connection timeout"),
    OPT_DEF("retries", 'r', 1, "Command reties"),
    OPT_DEF_END
};

static int parse_mcumgr_options(struct cli_options *copts)
{
    int argc = copts->argc;
    char *const *argv = copts->argv;
    int opt;

    reset_getopt();

    while ((opt = getopt(argc, argv, OPTSTR "hs:t:vV-:")) != -1) {
        const char *arg = optarg;
        if (opt == '-') {
            /* arg contains long option without -- */
            const struct longopt *lo = find_long_opt(cli_longopts, arg);

            if (!lo) {
                copts->argc = argc - (optind - 1);
                copts->argv += (optind - 1);
                return CLI_UNRECOGNIZED_OPTION;
            }
            opt = lo->opt;
            if (lo->arg_num) {
                arg = get_long_optarg(lo, argc, argv, arg);
                if (!arg) {
                    copts->argc = argc - optind;
                    copts->argv += optind;
                    return CLI_MISSING_ARGUMENT;
                }
            }
        }

        switch (opt) {
            case 'h':
                copts->help = 1;
                break;
            case 's':
                copts->connstring = get_optarg(arg);
                break;
            case 1:
                copts->conntype = get_optarg(arg);
                break;
            case 't':
            {
                int ret, to;
                ret = get_int_optarg(arg, &to);
                if (ret) {
                    copts->argc = argc - (optind - 1);
                    copts->argv += (optind - 1);
                    return ret;
                }
                copts->timeout = to;
                break;
            }
            case 'r':
            {
                int ret, rt;
                ret = get_int_optarg(arg, &rt);
                if (ret) {
                    copts->argc = argc - (optind - 1);
                    copts->argv += (optind - 1);
                    return ret;
                }
                copts->retries = rt;
                break;
            }
            case 'v':
                ++copts->verbose;
                break;
            case 'V':
                copts->version = 1;
                break;
            case '?':
                /* unrecognized option */
                copts->optopt = optopt;
                return CLI_UNRECOGNIZED_OPTION;
            case ':':
                /* missing required arg */
                copts->optopt = optopt;
                return CLI_MISSING_ARGUMENT;
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
    if (copts->argc <= 0) {
        copts->argv = NULL;
        /* no command */
        copts->subcmd = CMD_NONE;
        return CLI_MISSING_COMMAND;
    }

    return parse_subcommand_options(subcmds, copts);
}


/**
 * @brief parse cli options
 *
 * @param argc  Argument count
 * @param argv  Arguments
 * @param copts Where to store parsed options
 *
 * @retval 0                         parsing success
 * @retval -EINVAL                   invalid argument provided (API usage error)
 * @retval CLI_UNRECOGNIZED_OPTION   unrecognized option or (sub)command
 * @retval CLI_MISSING_ARGUMENT      missing option argument.
 * @retval CLI_ACCESS_ARGUMENTS      access argument
 * @retval CLI_MISSING_COMMAND       missing required argument or (sub)command
 * @retval CLI_INVALID_ARGUMENT      option argument or positional argument is malformed/out of range
 *
 */
int parse_cli_options(int argc, char *const *argv, struct cli_options *copts)
{
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

    return parse_mcumgr_options(copts);
}

static const struct subcmd mcumgr[] = {
    CMD_DEF_SUB("mcumgr", CMD_NONE, parse_mcumgr_options, cli_longopts, "Manage devices", subcmds),
    CMD_DEF_END
};

static const int print_padlen = 20;

static void print_subcommands(const struct subcmd *subs)
{
    const int padlen = print_padlen;
    if (!subs) {
        return;
    }
    for (const struct subcmd *sc = subs; sc->name; ++sc) {
        int len = strlen(sc->name);
        if (len >= padlen) len = 0; else len = padlen - len;
        fprintf(stderr, "   %s  %*s%s\n", sc->name, len, "", sc->description);
    }
}

static void print_options(const struct longopt *lopts)
{
    if (!lopts) {
        return;
    }

    for (const struct longopt *lo = lopts; lo->name; ++lo) {
        char opt = 0;
        const char *description = lo->description ? lo->description : "";
        int padlen = print_padlen - sizeof("-X, --") + 1;

        if (lo->opt >= '0' && lo->opt <= 'z') {
            opt = (char) lo->opt;
        }
        if (lo->name) {
            int len = strlen(lo->name);
            if (len >= padlen) padlen = 0; else padlen = padlen - len;
        }
        if (opt && lo->name) {
            fprintf(stderr, "   -%c, --%s  %*s%s\n", opt, lo->name, padlen, "", description);
        } else if (opt) {
            fprintf(stderr,  "   -%c       %*s%s\n", opt, padlen, "", description);
        } else if (lo->name) {
            fprintf(stderr,  "       --%s  %*s%s\n", lo->name, padlen, "", description);
        }
    }
}

static void print_usage_subcommand(const char* prgname, const struct subcmd *sc)
{
    const char *optstr = "options";

    fprintf(stderr, "Usage: %s [%s] ", prgname, optstr);

    if (sc->cmd != CMD_NONE) {
        /* TODO: better, fixme: sub command of subcommand (e.g. image list, not correct) */
        if (sc->subcmds) {
            if (sc->lopts) {
                fprintf(stderr, "%s [%s_%s] <cmd> ...\n", sc->name, sc->name, optstr);
            } else {
                fprintf(stderr, "%s <cmd> ...\n", sc->name);
            }
        } else if (sc->lopts) {
            if (sc->args_usage) {
                fprintf(stderr, "%s [%s_%s] %s\n", sc->name, sc->name, optstr, sc->args_usage);
            } else {
                fprintf(stderr, "%s [%s_%s]\n", sc->name, sc->name, optstr);
            }
        } else {
            if (sc->args_usage) {
                fprintf(stderr, "%s [%s_%s] %s\n", sc->name, sc->name, optstr, sc->args_usage);
            } else {
                fprintf(stderr, "%s\n", sc->name);
            }
        }
    } else {
        fprintf(stderr, "<cmd> ...\n");
    }

    fprintf(stderr, "%s\n", sc->description);

    if (sc->subcmds) {
        fprintf(stderr, "\nAvaliable subcommands:\n");
        print_subcommands(sc->subcmds);
    }
    fprintf(stderr, "\nOptions:\n");
    if (sc->lopts) {
        print_options(sc->lopts);
    } else {
        print_options(common_longopts);
    }
    if (sc->subcmds) {
        fprintf(stderr, "\nRun %s %s -h for detailed command description\n", prgname, sc->name);
    }
}


static void _usage_subcommand(const char *prgname, enum subcommand subcmd, const struct subcmd *subcmd_list)
{
    for (const struct subcmd *sc = subcmd_list; sc->name; ++sc) {
        if (sc->cmd == subcmd) {
            print_usage_subcommand(prgname, sc);
        } else if (sc->subcmds) {
            _usage_subcommand(prgname, subcmd, sc->subcmds);
        }
    }
}


void usage_subcommand(const char *prgname, enum subcommand subcmd)
{
    _usage_subcommand(prgname, subcmd, mcumgr);
}

void usage_mcumgr(const char *prgname)
{
    fprintf(stderr, "%s %s\n", mcumgr->name, version);
    usage_subcommand(prgname, CMD_NONE);
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
