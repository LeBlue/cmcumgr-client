/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MGMT_OS_H
#define MGMT_OS_H

#include <stdint.h>
#include "mgmt.h"

/* core OS commands */

/**
 * @brief echo request parameters
 *
 */
struct mgmt_echo_req {
    const char *echo_str;
};

#define ECHO_STR_MAX_LEN 128 /**< Maximum allowed echo request string length */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief echo response values
 *
 */
struct mgmt_echo_rsp {
    int64_t mgmt_rc; /**< Mgmt response code */
    char echo_str[ECHO_STR_MAX_LEN + 1]; /**< Echo response string */
};

/**
 * @brief Create encoded OS echo request packet
 *
 * @param buf       buffer where to store the request packet data
 * @param sz        @p buf buffer size
 * @param req       echo request parameters
 * @return ssize_t  The size of the request stored in @p buf or -ENOBUFS, if the supplied buffer is to short for the encoded
 */
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

/**
 * @brief Create encoded OS reset request packet
 *
 * @param buf       buffer where to store the request packet data
 * @param sz        @p buf buffer size
 * @param req       echo request parameters
 * @return ssize_t  The size of the request stored in @p buf or -ENOBUFS, if the supplied buffer is to short for the encoded
 */
ssize_t mgmt_create_os_reset_req(uint8_t *buf, size_t sz);

/**
 * @brief Check and decode the mgmt OS reset response SMP message
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
int mgmt_os_reset_decode_rsp(uint8_t *buf, size_t sz, struct mgmt_rc *rsp);

#ifdef __cplusplus
}
#endif

#endif