/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#include "cmd_common.h"
#include "smp_transport.h"
#include "utils.h"


int cmd_run(struct smp_transport *transport, uint8_t *buf, size_t reqsz, size_t bufsz)
{
    int rc = -EINVAL;

    for (int retries = transport->retries; retries >= 0; --retries) {
        rc = transport->ops->write(transport, buf, reqsz);

        /* TODO: try reconnecting ?*/
        if (rc < 0) {
            return rc;
        }

        rc = transport->ops->read(transport, buf, bufsz);
        if (!rc) {
            return 0;
        } else if (rc != -ETIMEDOUT) {
            return rc;
        }
    }
    return rc;
}


int cmd_run_rc_rsp(struct smp_transport *transport, uint8_t *buf, size_t reqsz, size_t bufsz, struct mgmt_rc *rsp)
{
    int rc = cmd_run(transport, buf, reqsz, bufsz);

    if (rc > 0) {
        if (transport->verbose) {
            ehexdump(buf, rc, "rc");
        }

        rc = mgmt_decode_err_rsp(buf, rc, &rsp->mgmt_rc);

        if (rc < 0 || (rc == 0 && rsp->mgmt_rc != 0)) {
            return rc;
        }
        rsp->mgmt_rc = 0;

    }

    return rc;
}

