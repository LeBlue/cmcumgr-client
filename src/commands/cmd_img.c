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
#include <errno.h>

#include "cmd_img.h"
#include "mgmt_img.h"
#include "mgmt_hdr.h"

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



struct upload_state {
    struct upload_progress progress;
    uint8_t seq;
    size_t offs;
};

int cmd_img_run_image_upload(struct smp_transport *transport, struct mgmt_image_upload_req *req, struct mgmt_rc *rsp, upload_progress_fn cb)
{
    uint8_t buf[CMD_BUF_SZ];
    ssize_t cnt;
    struct upload_state state = {0};
    int rc, buflen;
    uint8_t file_buf[256];
    size_t fsz = sizeof(file_buf);

    rsp->mgmt_rc = 0;

    state.progress.size = req->image.file_sz;

    rc = req->reader.op->open(req->reader.fh);

    if (rc) {
        return rc;
    }

    if (cb) {
        cb(&state.progress);
    }

    rc = req->reader.op->read(req->reader.fh, file_buf, &fsz, 0);
    if (rc < 0) {
        return rc;
    }

    cnt = mgmt_create_image_upload_seg0_req(buf, sizeof(buf), req->image.file_sz, file_buf, req->image.hash, sizeof(file_buf));

    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }

    if (transport->verbose) {
        ehexdump(buf, cnt, "image upload req0");
    }


    mgmt_header_update_seq(buf, state.seq);

    rc = cmd_run(transport, buf, cnt, sizeof(buf));

    if (rc < 0) {
        fprintf(stderr, "read fail %d\n", rc);
        return rc;
    }

    state.seq++;
    buflen = rc;

    if (transport->verbose) {
        ehexdump(buf, buflen, "image upload seq0 rsp");
    }

    rc = mgmt_img_upload_decode_rsp(buf, sizeof(buf), &state.offs, rsp);
    if (rc) {
        printf("decode faile rsp 0\n");
        return rc;
    } else {
        if (rsp->mgmt_rc > 0) {
            return 0;
        }
    }

    if (state.offs > sizeof(file_buf)) {
        printf("Upload continue\n");
    }

    while (state.offs < req->image.file_sz) {
        printf("Sending offset: %d\n", (int)state.offs);
        fsz = sizeof(file_buf);
        rc = req->reader.op->read(req->reader.fh, file_buf, &fsz, state.offs);
        if (rc < 0) {
            printf("File read fail at %d\n", (int)state.offs);
            return rc;
        }

        size_t seglen;
        if (req->image.file_sz - state.offs < sizeof(file_buf)) {
            seglen = req->image.file_sz - state.offs;
            printf("Last segment: %d\n", (int) seglen);
        } else {
            seglen = sizeof(file_buf);
        }

        cnt = mgmt_create_image_upload_segX_req(buf, sizeof(buf), state.offs, file_buf, seglen);

        if (cnt < 0) {
            fprintf(stderr, "message encoding issue %zu\n", cnt);
            return (int)cnt;
        }

        if (transport->verbose) {
            ehexdump(buf, cnt, "image upload reqX");
        }


        mgmt_header_update_seq(buf, state.seq);

        rc = cmd_run(transport, buf, cnt, sizeof(buf));

        if (rc < 0) {
            fprintf(stderr, "read fail %d\n", rc);
            return rc;
        }

        state.seq++;
        buflen = rc;

        if (transport->verbose) {
            ehexdump(buf, buflen, "image upload seqX rsp");
        }
        size_t old_off = state.offs;

        rc = mgmt_img_upload_decode_rsp(buf, sizeof(buf), &state.offs, rsp);
        if (rc) {
            if (rsp->mgmt_rc > 0) {
                printf("Mgmt err rsp X: %d\n", (int) rsp->mgmt_rc);
                return 0;
            } else {
                printf("decode failed rsp X\n");
            }
            return rc;
        }


        printf("New off: %d\n", (int)state.offs);
        if (state.offs <= old_off) {
            printf("FW upload stall\n");
            return -EPROTO;
        }

        if (cb) {
            int old_percent = state.progress.percent;
            state.progress.off = state.offs;
            state.progress.percent = (state.progress.off * 100) / state.progress.size;
            if (old_percent != state.progress.percent) {
                cb(&state.progress);
            }
        }
    }

    return 0;
}

