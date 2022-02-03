/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CMD_IMG_H
#define CMD_IMG_H

#include "mgmt_img.h"
#include "smp_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

int cmd_img_run_image_list(struct smp_transport *transport, struct mgmt_image_state_rsp *rsp);

#ifdef __cplusplus
}
#endif

#endif
