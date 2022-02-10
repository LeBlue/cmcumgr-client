/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CMD_IMG_H
#define CMD_IMG_H

#include "mgmt_img.h"
#include "smp_transport.h"

struct upload_progress {
    int percent;
    uint32_t size;
    uint32_t off;
};

typedef void (*upload_progress_fn)(struct upload_progress *progress);

#ifdef __cplusplus
extern "C" {
#endif

int cmd_img_run_image_list(struct smp_transport *transport, struct mgmt_image_state_rsp *rsp);
int cmd_img_run_image_test(struct smp_transport *transport, struct mgmt_image_test_req *req, struct mgmt_image_state_rsp *rsp);
int cmd_img_run_image_confirm(struct smp_transport *transport, struct mgmt_image_state_rsp *rsp);
int cmd_img_run_image_erase(struct smp_transport *transport, struct mgmt_rc *rsp);
int cmd_img_run_image_upload(struct smp_transport *transport, struct mgmt_image_upload_req *req, struct mgmt_rc *rsp, upload_progress_fn cb);

#ifdef __cplusplus
}
#endif

#endif
