/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CMD_COMMON_H
#define CMD_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include "mgmt.h"

struct smp_transport;

#define CMD_BUF_SZ 512

#ifdef __cplusplus
extern "C" {
#endif

int cmd_run(struct smp_transport *transport, uint8_t *buf, size_t reqsz, size_t bufsz);
int cmd_run_rc_rsp(struct smp_transport *transport, uint8_t *buf, size_t reqsz, size_t bufsz, struct mgmt_rc *mgmt_rc);

#ifdef __cplusplus
}
#endif

#endif
