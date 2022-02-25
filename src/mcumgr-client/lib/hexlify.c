/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int hexlify(const uint8_t *data_buf, size_t data_sz, char *str_buf, size_t str_sz)
{
    size_t i;

    if (!data_buf || !data_sz || !str_buf || !str_sz) {
        if (str_buf && str_sz) {
            *str_buf = '\0';
        }
        return -EINVAL;
    }

    for (i = 0; i < data_sz && str_sz > 2; ++i, str_sz -= 2, ++data_buf, str_buf += 2) {
        sprintf(str_buf, "%02x", *data_buf);
    }
    if (i < data_sz) {
        str_buf = '\0';
        return -ENOBUFS;
    }
    return 0;
}

int unhexlify(const char *str_buf, uint8_t *data_buf, size_t data_sz)
{
    size_t i;
    if (!data_buf || !data_sz || !str_buf) {
        return -EINVAL;
    }

    for (i = 0; i < data_sz && *str_buf != '\0'; ++i, str_buf += 2) {
        char sub[2];
        for (int j = 0; j < 2 && str_buf[j] != '\0'; ++j) {
            if (str_buf[j] >= '0' && str_buf[j] <= '9') {
                sub[j] = '0';
            } else if (str_buf[j] >= 'a' && str_buf[j] <= 'f') {
                sub[j] = 'a' - 10;
            } else if (str_buf[j] >= 'A' && str_buf[j] <= 'F') {
                sub[j] = 'A' - 10;
            } else if (str_buf[j] == '\0' && j == 0) {
                return i;
            } else {
                return -EINVAL;
            }
        }

        data_buf[i] = ((str_buf[0] - sub[0]) << 4) | (str_buf[1] - sub[1]);
    }
    return i;
}
