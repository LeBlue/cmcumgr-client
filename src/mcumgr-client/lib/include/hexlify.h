/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIB_HEXLIFY_H
#define LIB_HEXLIFY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Print binary data as ASCII hex string
 *
 * @param data_buf   Data to print
 * @param data_sz    Data size
 * @param str_buf    Buffer to print hex string into, will be zero-terminated.
 * @param str_sz     Size of @p str_buf in bytes
 *
 * @retval        0  On success
 * @retval  -EINVAL  Invalid arguments
 * @retval -ENOBUFS  @p str_buf to short. Data in @p ptr_buf is still valid but truncated.
 */
int hexlify(const uint8_t *data_buf, size_t data_sz, char *str_buf, size_t str_sz);

/**
 * @brief Convert ASCII hex string to binary data
 *
 * @param str_buf    ASCII hex string to convert, must be zero-terminated
 * @param data_buf   Buffer to save binary representation
 * @param data_sz    Size of @p data_buf in bytes
 *
 * @retval  >= 0     On success, number of converted bytes in @p data_buf.
 * @retval  -EINVAL  Invalid arguments or invalid @p str_buf contents
 */
int unhexlify(const char *str_buf, uint8_t *data_buf, size_t data_sz);

#ifdef __cplusplus
}
#endif

#endif
