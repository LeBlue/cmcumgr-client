/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MGMT_UTILS_H
#define MGMT_UTILS_H

#include <stdint.h>
#include <stddef.h>

#include "mgmt_img.h"

#define SLOT_FLAGS_STR_MAX sizeof("active,confirmed,pending,permanent")
struct mgmt_slot_state;
struct mgmt_image_state;


#ifdef __cplusplus
extern "C" {
#endif

int slot_flags_to_str(char *flags_buf, const struct mgmt_slot_state *slot);

int data_buf_to_str(const uint8_t *data_buf, size_t data_sz, char *str_buf, size_t str_sz);

static inline int hexlify(const uint8_t *data_buf, size_t data_sz, char *str_buf, size_t str_sz)
{
    return data_buf_to_str(data_buf, data_sz, str_buf, str_sz);
}

int str_to_data_buf(const char *str_buf, uint8_t *data_buf, size_t data_sz);

static inline int unhexlify(const char *str_buf, uint8_t *data_buf, size_t data_sz)
{
    return str_to_data_buf(str_buf, data_buf, data_sz);
}

void print_image_slot(struct mgmt_slot_state *slot);

void print_image_slot_state(struct mgmt_image_state *slot_state);


#ifdef _cplusplus
}
#endif

#endif
