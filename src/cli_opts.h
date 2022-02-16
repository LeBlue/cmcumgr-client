/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CLI_OPTS_H
#define CLI_OPTS_H

#include "mcumgr.h"

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


int usage_common(const char *prgname);
int usage_reset(const char *prgname);
int usage_echo(const char *prgname);

#endif
