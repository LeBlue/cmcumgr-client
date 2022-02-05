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

void print_image_slot(struct mgmt_slot_state *slot);

void print_image_slot_state(struct mgmt_image_state *slot_state);


#ifdef _cplusplus
}
#endif

#endif
