/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */


#define TXBUF_SZ 2100
#define FIRST_SEG_TMO 16
#define NEXT_SEG_TMO 1

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "mgmt_img.h"
#include "smp_transport.h"
#include "utils.h"
#include "cmd_common.h"

int cmd_img_run_image_list(struct smp_transport *transport, struct mgmt_image_state_rsp *rsp)
{
    uint8_t buf[CMD_BUF_SZ];
    ssize_t cnt;
    int rc, buflen;

    cnt = mgmt_create_image_list_req(buf, sizeof(buf));
    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }

    if (transport->verbose) {
        ehexdump(buf, cnt, "image list req");
    }

    rc = cmd_run(transport, buf, cnt, sizeof(buf));

    if (rc < 0) {
        fprintf(stderr, "read fail %d\n", rc);
        return rc;
    }

    buflen = rc;

    if (transport->verbose) {
        ehexdump(buf, buflen, "list rsp");
    }

    return mgmt_img_decode_list_rsp(buf, buflen, rsp);
}

int cmd_img_run_image_test(struct smp_transport *transport, struct mgmt_image_test_req *req, struct mgmt_image_state_rsp *rsp)
{
    uint8_t buf[CMD_BUF_SZ];
    ssize_t cnt;
    int rc, buflen;

    cnt = mgmt_create_image_test_req(buf, sizeof(buf), req);
    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }

    if (transport->verbose) {
        ehexdump(buf, cnt, "image list req");
    }

    rc = cmd_run(transport, buf, cnt, sizeof(buf));

    if (rc < 0) {
        fprintf(stderr, "read fail %d\n", rc);
        return rc;
    }

    buflen = rc;

    if (transport->verbose) {
        ehexdump(buf, buflen, "test rsp");
    }

    return mgmt_img_decode_test_rsp(buf, buflen, rsp);
}


int cmd_img_run_image_confirm(struct smp_transport *transport, struct mgmt_image_state_rsp *rsp)
{
    uint8_t buf[CMD_BUF_SZ];
    ssize_t cnt;
    int rc, buflen;

    cnt = mgmt_create_image_confirm_req(buf, sizeof(buf));
    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }

    if (transport->verbose) {
        ehexdump(buf, cnt, "image list req");
    }

    rc = cmd_run(transport, buf, cnt, sizeof(buf));

    if (rc < 0) {
        fprintf(stderr, "read fail %d\n", rc);
        return rc;
    }

    buflen = rc;

    if (transport->verbose) {
        ehexdump(buf, buflen, "confirm rsp");
    }

    return mgmt_img_decode_confirm_rsp(buf, buflen, rsp);
}


int cmd_img_run_image_erase(struct smp_transport *transport, struct mgmt_rc *rsp)
{
    uint8_t buf[CMD_BUF_SZ];
    ssize_t cnt;

    cnt = mgmt_create_image_erase_req(buf, sizeof(buf));
    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }

    if (transport->verbose) {
        ehexdump(buf, cnt, "image list req");
    }

    return cmd_run_rc_rsp(transport, buf, cnt, sizeof(buf), rsp);
}
