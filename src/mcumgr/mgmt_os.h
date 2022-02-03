/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MGMT_OS_H
#define MGMT_OS_H

#include <stdint.h>
#include "mgmt.h"

/* core OS commands */

/* OS ECHO */
struct mgmt_echo_req {
    const char *echo_str;
};

#define ECHO_STR_MAX_LEN 128

struct mgmt_echo_rsp {
    int64_t mgmt_rc;
    char echo_str[ECHO_STR_MAX_LEN + 1];
};

ssize_t mgmt_create_os_echo_req(uint8_t *buf, size_t sz, const struct mgmt_echo_req *req);

/**
 * @brief Check and return the mgmt echo return message from an SMP message
 *
 * @param buf       The buffer holding the message
 * @param sz        Size of the buffer
 * @param rsp       pointer where to save the decoded response.
 * @return          0 on success and error code otherwise
 *
 * @retval 0 Successful execution, @p rsp is valid.
 * @retval -EINVAL Argument validation failed
 * @retval -ENODATA @p buf too short to hold SMP header or not a complete SMP packet.
 * @retval -ENOMSG SMP payload decoding error or unexpected format, e.g. not a map, requested value has wrong format, ...
 */
int mgmt_os_echo_decode_rsp(const uint8_t *buf, size_t sz, struct mgmt_echo_rsp *rsp);

/* OS reset */
ssize_t mgmt_create_os_reset_req(uint8_t *buf, size_t sz);
int mgmt_os_reset_decode_rsp(uint8_t *buf, size_t sz, struct mgmt_rc *rsp);

#endif