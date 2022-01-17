/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MCUBOOT_IMAGE_H
#define MCUBOOT_IMAGE_H

#include "mgmt_rc.h"

struct file_reader;

struct mcuboot_image {
    struct image_version version;
    uint32_t img_sz;
    uint8_t magic_ok;
    uint8_t hash[32];
};

int image_version_to_str(char *vbuf, const struct image_version *version);

#define IMAGE_HASH_STR_MAX 65
int image_hash_to_str(char *hbuf, const uint8_t hash[32]);


int mcuboot_image_file_parse(struct file_reader *reader, struct mcuboot_image *image_info);
void mcuboot_image_info_print(const struct mcuboot_image *image_info);

#endif
