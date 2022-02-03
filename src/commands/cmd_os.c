/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "mgmt_os.h"
#include "smp_transport.h"
#include "utils.h"

int cmd_os_run_echo(struct smp_transport *transport, const struct mgmt_echo_req *req, struct mgmt_echo_rsp *rsp)
{
    uint8_t buf[512];
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

    rc = transport->ops->write(transport, buf, cnt);
    if (rc < 0) {
        fprintf(stderr, "write fail %d\n", rc);
        return rc;
    }

    rc = transport->ops->read(transport, buf, sizeof(buf));
    if (rc < 0) {
        fprintf(stderr, "read fail %d\n", rc);
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
    uint8_t buf[512];
    ssize_t cnt;
    int rc;
    int buflen;

    cnt = mgmt_create_os_reset_req(buf, sizeof(buf));
    if (cnt < 0) {
        fprintf(stderr, "message encoding issue %zu\n", cnt);
        return (int)cnt;
    }
    if (transport->verbose) {
        hexdump(buf, cnt, "reset req");
    }

    rc = transport->ops->write(transport, buf, cnt);

    if (rc < 0) {
        fprintf(stderr, "write fail %d\n", rc);
        return rc;
    }

    rc = transport->ops->read(transport, buf, cnt);

    if (rc < 0) {
        fprintf(stderr, "read fail %d\n", rc);
        return rc;
    }

    if (transport->verbose) {
        ehexdump(buf, rc, "reset rsp");
    }

    buflen = rc;

    rc = mgmt_decode_err_rsp(buf, buflen, &rsp->mgmt_rc);

    if (rc < 0 || (rc == 0 && rsp->mgmt_rc != 0)) {
        fprintf(stdout, "Device reset failed\n");
        return rc;
    }
    rsp->mgmt_rc = 0;

    if (transport->verbose) {
        fprintf(stdout, "Device reset\n");
    }

    return 0;
}

