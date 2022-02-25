/*
 * Copyright (c) 2020-2021 Siddharth Chandrasekaran <sidcha.dev@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIB_UTILS_H_
#define _LIB_UTILS_H_

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Dumps an array of bytes in HEX and ASCII formats for debugging. `head`
 * is string that is printed before the actual bytes are dumped.
 *
 * Example:
 * 	int len;
 * 	uint8_t data[MAX_LEN];
 * 	len = get_data_from_somewhere(data, MAX_LEN);
 * 	hexdump(data, len, "Data From Somewhere");
 */
void hexdump(const void *data, size_t len, const char *fmt, ...);
void ehexdump(const void *p, size_t len, const char *fmt, ...);


#endif /* _UTILS_UTILS_H_ */
