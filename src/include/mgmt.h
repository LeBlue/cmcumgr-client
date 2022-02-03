/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MGMT_H
#define MGMT_H

#include <stdint.h>
#include <stddef.h>

// /* common functions and definitions */
// struct mgmt_rc {
//     int64_t mgmt_rc;
// };

/* buffer length required for printing version, includes \0 */
#define IMAGE_VERSION_STR_MAX 25

struct image_version {
    uint8_t major;
    uint8_t minor;
    uint16_t revision;
    uint32_t build_num;
};

// int mgmt_decode_err_rsp(const uint8_t *buf, size_t sz, int64_t *mgmt_err);

#endif