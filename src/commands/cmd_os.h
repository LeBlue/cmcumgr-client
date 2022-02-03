/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CMD_OS_H
#define CMD_OS_H

#include "mgmt.h"
#include "mgmt_img.h"
#include "smp_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

int cmd_os_run_echo(struct smp_transport *transport, const struct mgmt_echo_req *req, struct mgmt_echo_rsp *rsp);
int cmd_os_run_reset(struct smp_transport *transport, struct mgmt_rc *rsp);

#ifdef __cplusplus
}
#endif

#endif
