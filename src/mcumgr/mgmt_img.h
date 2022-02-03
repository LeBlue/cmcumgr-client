/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MGMT_IMG_H
#define MGMT_IMG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#include "mgmt.h"
#include "mcuboot_img.h"

/* image update common */
struct mgmt_slot_state {
    struct image_version version;
    uint8_t slot;
    uint8_t pending;
    uint8_t bootable;
    uint8_t active;
    uint8_t confirmed;
    uint8_t permanent;

    uint8_t hash[32];
};


#define MGMT_IMAGE_STATE_SLOTS_MAX 2

struct mgmt_image_state {
    struct mgmt_slot_state slot[MGMT_IMAGE_STATE_SLOTS_MAX];
    uint8_t num_slots;
    int64_t split_status;
};

struct mgmt_image_state_rsp {
    int64_t mgmt_rc;
    struct mgmt_image_state state;
};
int mgmt_img_decode_state_rsp(const uint8_t *buf, size_t sz, int64_t *mgmt_err, struct mgmt_image_state *state);


/* image erase */
ssize_t mgmt_create_image_erase_req(uint8_t *buf, size_t sz);

/* image list */
ssize_t mgmt_create_image_list_req(uint8_t *buf, size_t sz);
int mgmt_img_decode_list_rsp(const uint8_t *buf, size_t sz, struct mgmt_image_state_rsp *rsp);

/* image test */
struct mgmt_image_test_req {
    uint8_t fw_sha[32];
    bool confirm;
};

ssize_t mgmt_create_image_test_req(uint8_t *buf, size_t sz, struct mgmt_image_test_req *req);
int mgmt_img_decode_test_rsp(const uint8_t *buf, size_t sz, struct mgmt_image_state_rsp *rsp);

/* image confirm */
ssize_t mgmt_create_image_confirm_req(uint8_t *buf, size_t sz);
int mgmt_img_decode_confirm_rsp(const uint8_t *buf, size_t sz, struct mgmt_image_state_rsp *rsp);

#endif