/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "mgmt_os.h"
#include "smp_transport.h"
#include "cmd_common.h"
#include "utils.h"

int cmd_os_run_echo(struct smp_transport *transport, const struct mgmt_echo_req *req, struct mgmt_echo_rsp *rsp)
{
    uint8_t buf[CMD_BUF_SZ];
    ssize_t cnt;
    int rc, buflen;

    cnt = mgmt_create_os_echo_req(buf, sizeof(buf), req);
    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }

    if (transport->verbose) {
        ehexdump(buf, cnt, "echo req");
    }

    rc = cmd_run(transport, buf, cnt, sizeof(buf));
    if (rc < 0) {
        fprintf(stderr, "Failed to run echo %d\n", rc);
        return rc;
    }

    buflen = rc;
    if (transport->verbose) {
        ehexdump(buf, buflen, "echo rsp");
    }

    return mgmt_os_echo_decode_rsp(buf, buflen, rsp);
}



int cmd_os_run_reset(struct smp_transport *transport, struct mgmt_rc *rsp)
{
    uint8_t buf[CMD_BUF_SZ];
    ssize_t cnt;

    cnt = mgmt_create_os_reset_req(buf, sizeof(buf));
    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }
    if (transport->verbose) {
        ehexdump(buf, cnt, "reset req");
    }

    return cmd_run_rc_rsp(transport, buf, cnt, sizeof(buf), rsp);
}
