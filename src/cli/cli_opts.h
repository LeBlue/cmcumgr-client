/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CLI_OPTS_H
#define CLI_OPTS_H

#include "mgmt_img.h"
#include "mgmt_os.h"


#define CLI_UNRECOGNIZED_OPTION -ENOENT
#define CLI_MISSING_ARGUMENT -ENODATA
#define CLI_MISSING_COMMAND -ENOMSG
#define CLI_ACCESS_ARGUMENTS -E2BIG
/* EINVAL is used for API usage error, this one is invalid cli option argument */
#define CLI_INVALID_ARGUMENT -EBADMSG


typedef enum subcommand {
    CMD_NONE = 0,
    CMD_IMAGE,
    CMD_IMAGE_INFO,
    CMD_IMAGE_LIST,
    CMD_IMAGE_TEST,
    CMD_IMAGE_CONFIRM,
    CMD_IMAGE_UPLOAD,
    CMD_IMAGE_ERASE,
    CMD_ECHO,
    CMD_RESET,
    CMD_NUM,
} subcommand;


#define CMD_POS_ARGS_MAX 1
struct cmd_posargs {
    const char *arg[CMD_POS_ARGS_MAX];
};

struct cmd_analyze_opts {
    const char *file_name;
};


struct cli_options {
    const char *prgname;
    const char *connstring;
    const char *conntype;
    /* remaining args after (partial) parsing */
    int argc;
    char *const *argv;

    /* some flags */
    int help;
    int version;
    int verbose;
    char optopt;
    int timeout;
    int retries;

    /* command string  */
    const char *cmd;
    /* command id */
    subcommand subcmd;
    /* subcommand opts can share mem */
    union {
        /* generic positional args */
        struct cmd_posargs positional;

        /* os */
        struct mgmt_echo_req os_echo;
        /* image */
        struct mgmt_image_test_req img_test;

        struct mgmt_image_upload_req img_upload;

        struct cmd_analyze_opts analyze;
    } cmdopts;
};


int parse_cli_options(int argc, char *const *argv, struct cli_options *copts);


void usage_mcumgr(const char *prgname);

void usage_subcommand(const char *prg_name, enum subcommand subcmd);


#endif
