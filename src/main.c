/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include "utils.h"
#include "mcumgr.h"
#include "file_reader_unix.h"
#include "byteordering.h"
#include "cli_opts.h"
#include "file_reader.h"

#include "mgmt_img.h"

#include "cmd_img.h"
#include "cmd_os.h"

#include "smp_serial.h"
#include "smp_transport.h"

const char *cmdname;



void print_usage_or_error(struct cli_options *copts, int rc)
{
    switch (rc) {
        case 0:
            if (copts->version) {
                printf("%s\n", VERSION);
                exit(0);
            } else if (copts->help) {
                usage_common(copts->prgname);
                exit(0);
            }
            break;
        case -ENODATA:
            if (copts->optopt) {
                fprintf(stderr, "Missing option argument to '-%c'\n", copts->optopt);
            } else if (copts->cmd) {
                fprintf(stderr, "Missing argument to %s\n", copts->cmd);
            } else {
                fprintf(stderr, "Missing argument\n");
            }
            exit(1);

        case -E2BIG:
            if (copts->argv && copts->argv[0]) {
                fprintf(stderr, "Access argument(s) after: %s\n", copts->argv[0]);
            } else {
                fprintf(stderr, "Access argument(s)\n");
            }
            exit(1);

        case -EINVAL:
            /* bug here in parsing code */
            fprintf(stderr, "Options parsing failed\n");
            exit(1);
        case -ENOENT:
        {
            const char *errmsg;
            const char *optstr;
            char tmpstr[] = "-?";
            if (copts->optopt || copts->argv[0][0] == '-') {
                errmsg = "Unrecognized option";
                if (copts->optopt) {
                    tmpstr[1] = (char)copts->optopt;
                    optstr = tmpstr;
                } else {
                    optstr = copts->argv[0];
                }
            } else {
                errmsg = "Unrecognized command";
                optstr = copts->argv[0];
            }
            if (copts->cmd) {
                fprintf(stderr, "%s '%s' for '%s'\n", errmsg, optstr, copts->cmd);
            } else {
                fprintf(stderr, "%s '%s'\n", errmsg, optstr);
            }
            exit(1);
        }
        case -ENOMSG:
            if (copts->cmd) {
                fprintf(stderr, "Missing subcommand for '%s'\n", copts->cmd);
            } else {
                fprintf(stderr, "Missing subcommand\n");
            }
            exit(1);
        case -EBADMSG:
            fprintf(stderr, "Invalid format for argument '%s'\n", copts->argv[0]);
            exit(1);
        default:
            fprintf(stderr, "Options parsing failed: %s\n", strerror(-rc));
            exit(1);

            break;
    }
}

void print_mgmt_error(uint64_t mgmt_rc)
{
    const char *mgmt_rc_str = NULL;

    switch (mgmt_rc) {
        case MGMT_ERR_EOK:
            mgmt_rc_str = "OK";
            break;
        case MGMT_ERR_EUNKNOWN:
            mgmt_rc_str = "EUNKNOWN";
            break;
        case MGMT_ERR_ENOMEM:
            mgmt_rc_str = "ENOMEM";
            break;
        case MGMT_ERR_EINVAL:
            mgmt_rc_str = "EINVAL";
            break;
        case MGMT_ERR_ETIMEOUT:
            mgmt_rc_str = "ETIMEOUT";
            break;
        case MGMT_ERR_ENOENT:
            mgmt_rc_str = "ENOENT";
            break;
        case MGMT_ERR_EBADSTATE:
            mgmt_rc_str = "EBADSTATE";
            break;
        case MGMT_ERR_EMSGSIZE:
            mgmt_rc_str = "EMSGSIZE";
            break;
        case MGMT_ERR_ENOTSUP:
            mgmt_rc_str = "ENOTSUP";
            break;
        case MGMT_ERR_ECORRUPT:
            mgmt_rc_str = "ECORRUPT";
            break;
        default:
            break;
    }
    if (mgmt_rc_str) {
        fprintf(stdout, "MgmtError: %" PRId64 ", %s\n", mgmt_rc, mgmt_rc_str);
    } else {
        fprintf(stdout, "MgmtError: %" PRId64 "\n", mgmt_rc);
    }
}


int cli_execute_reset(struct smp_transport *transport)
{
    struct mgmt_rc rsp;

    int rc = cmd_os_run_reset(transport, &rsp);

    if (rc) {
        fprintf(stderr, "Failed to reset device: %s\n", strerror(-rc));
    } else if (rsp.mgmt_rc) {
        print_mgmt_error(rsp.mgmt_rc);
    }
    return rc;
}

int cli_execute_echo(struct smp_transport *transport, struct cli_options *copts)
{
    int rc;
    struct mgmt_echo_rsp rsp;
    struct mgmt_echo_req *req = &copts->cmdopts.os_echo;

    if (copts->verbose) {
        fprintf(stderr, "\necho: %s\n", req->echo_str);
    }
    rc = cmd_os_run_echo(transport, req, &rsp);

    if (rc >= 0) {
        if (rsp.mgmt_rc == 0) {
            printf("%s\n", rsp.echo_str);
        } else {
            print_mgmt_error(rsp.mgmt_rc);
        }
    } else {
        fprintf(stderr, "Failed to send echo: %s\n", strerror(-rc));
    }
    return rc;
}

int cli_execute_image_info(struct cli_options *copts)
{
    int rc;
    struct file_unix_handle fh;
    struct file_reader reader;
    struct mcuboot_image image_info;
    const char *fw_file = copts->cmdopts.analyze.file_name;

    rc = file_unix_init(&reader, &fh, fw_file);

    if (rc) {
        fprintf(stderr, "Failed to read %s: %s\n", fw_file, strerror(-rc));
        return rc;
    }
    rc = mcuboot_image_file_parse(&reader, &image_info);
    if (rc) {
        if (rc == -ENODATA) {
            fprintf(stderr, "Invalid file: %s\n", fw_file);
        } else {
            fprintf(stderr, "Failed to open file '%s': %s\n", fw_file, strerror(-rc));
        }
        return rc;
    }
    mcuboot_image_info_print(&image_info);
    return 0;
}



int cli_execute_image_list(struct smp_transport *transport, struct cli_options *copts)
{
    (void) copts;

    int rc;
    struct mgmt_image_state_rsp rsp;

    rc = cmd_img_run_image_list(transport, &rsp);

    if (rc >= 0) {
        if (rsp.mgmt_rc == 0) {
            print_image_slot_state(&rsp.state);
        } else {
            print_mgmt_error(rsp.mgmt_rc);
        }
    } else {
        fprintf(stderr, "Failed to list images: %s\n", strerror(-rc));
    }
    return rc;
}


int cli_execute_image_test(struct smp_transport *transport, struct cli_options *copts)
{
    int rc;
    struct mgmt_image_state_rsp rsp;

    rc = cmd_img_run_image_test(transport, &copts->cmdopts.img_test, &rsp);

    if (rc >= 0) {
        if (rsp.mgmt_rc == 0) {
            print_image_slot_state(&rsp.state);
        } else {
            print_mgmt_error(rsp.mgmt_rc);
        }
    } else {
        fprintf(stderr, "Failed to test image: %s\n", strerror(-rc));
    }
    return rc;
}


int cli_execute_image_confirm(struct smp_transport *transport, struct cli_options *copts)
{
    (void) copts;

    int rc;
    struct mgmt_image_state_rsp rsp;

    rc = cmd_img_run_image_confirm(transport, &rsp);

    if (rc >= 0) {
        if (rsp.mgmt_rc == 0) {
            print_image_slot_state(&rsp.state);
        } else {
            print_mgmt_error(rsp.mgmt_rc);
        }
    } else {
        fprintf(stderr, "Failed to confirm image: %s\n", strerror(-rc));
    }
    return rc;
}


int cli_execute_image_erase(struct smp_transport *transport, struct cli_options *copts)
{
    (void) copts;

    int rc;
    struct mgmt_rc rsp;

    rc = cmd_img_run_image_erase(transport, &rsp);

    if (rc == 0) {
        if (rsp.mgmt_rc == 0) {
            printf("Done\n");
        } else {
            print_mgmt_error(rsp.mgmt_rc);
        }
    } else {
        fprintf(stderr, "Failed to erase image: %s\n", strerror(-rc));
    }
    return rc;
}

static void upload_progress_cb(struct upload_progress *progress)
{
    printf("%d/%d (%d)\n", progress->off, progress->size, progress->percent);
}


int cli_execute_image_upload(struct smp_transport *transport, struct cli_options *copts)
{
    struct mgmt_rc rsp;
    int rc;
    struct mgmt_image_upload_req *req;

    struct file_unix_handle fh;
    const char *fw_file = copts->cmdopts.analyze.file_name;

    req = &copts->cmdopts.img_upload;

    rc = file_unix_init(&req->reader, &fh, fw_file);

    if (rc) {
        fprintf(stderr, "Failed to read %s: %s\n", fw_file, strerror(-rc));
        return rc;
    }
    rc = mcuboot_image_file_parse(&req->reader, &req->image);

    if (rc) {
        if (rc == -ENODATA) {
            fprintf(stderr, "Invalid file: %s\n", fw_file);
        } else {
            fprintf(stderr, "Failed to open file '%s': %s\n", fw_file, strerror(-rc));
        }
        return rc;
    }

    printf("Uploading:\n");
    mcuboot_image_info_print(&req->image);

    rc = cmd_img_run_image_upload(transport, req, &rsp, upload_progress_cb);

    if (rc == 0) {
        if (rsp.mgmt_rc == 0) {
            printf("Done\n");
        } else {
            print_mgmt_error(rsp.mgmt_rc);
        }
    } else {
        fprintf(stderr, "Failed to upload image: %s\n", strerror(-rc));
    }
    return rc;
}


int
main(int argc, char **argv)
{
    int rc;

    struct cli_options copts;
    struct serial_opts sopts;
    struct smp_transport transport = {0};
    struct smp_serial_handle serial_handle;


    rc = parse_cli_options(argc, argv, &copts);

    print_usage_or_error(&copts, rc);


    if (copts.subcmd == CMD_NONE) {
        fprintf(stderr, "No command given, try -h");
        exit(EXIT_FAILURE);
    }

    if (copts.connstring) {
        if (parse_serial_connstring(copts.connstring, &sopts)) {
            fprintf(stderr, "Failed to parse connstring: %s\n", copts.connstring);
            exit(EXIT_FAILURE);
        }

        if (serial_transport_init(&transport, &serial_handle, &sopts)) {
            fprintf(stderr, "Failed to init transport\n");
            exit(EXIT_FAILURE);
        }
        if (transport.ops->open(&transport)) {
            fprintf(stderr, "Failed to open transport\n");
            rc = EXIT_FAILURE;
            goto cleanup_transport;
        }
        transport.verbose = copts.verbose;
        transport.timeout = copts.timeout;
    }

    if (copts.subcmd != CMD_IMAGE_INFO) {
        if (!copts.conntype) {
            fprintf(stderr, "Missing conntype\n");
            exit(1);
        } else if (!copts.connstring) {
            fprintf(stderr, "Missing connstring\n");
            exit(1);
        }
    }

    switch (copts.subcmd) {
        case CMD_RESET:
            rc = cli_execute_reset(&transport);
            break;
        case CMD_ECHO:
            rc = cli_execute_echo(&transport, &copts);
            break;
        case CMD_IMAGE_UPLOAD:
            rc = cli_execute_image_upload(&transport, &copts);
            break;
        case CMD_IMAGE_INFO:
            rc = cli_execute_image_info( &copts);
            break;
        case CMD_IMAGE_LIST:
            rc = cli_execute_image_list(&transport, &copts);
            break;
        case CMD_IMAGE_TEST:
            rc = cli_execute_image_test(&transport, &copts);
            break;
        case CMD_IMAGE_CONFIRM:
            rc = cli_execute_image_confirm(&transport, &copts);
            break;
        case CMD_IMAGE_ERASE:
            rc = cli_execute_image_erase(&transport, &copts);
            break;
        default:
            fprintf(stderr, "Not implemented: %s\n", copts.cmd);
            rc = 1;
            break;
    }


cleanup_transport:
    if (transport.ops && transport.hd) {
        transport.ops->close(&transport);
    }

    fflush(stderr);
    fflush(stdout);

    if (rc) {
        exit(1);
    }
    return 0;
}
