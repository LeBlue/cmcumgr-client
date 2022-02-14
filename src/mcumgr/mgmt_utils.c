/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "mgmt_utils.h"
#include "hexlify.h"

/**
 * @brief           print @p version to string
 *
 * @param vbuf      output buffer, must be long enough and not NULL
 * @param version   The version to print
 * @return int
 */
int image_version_to_str(char *vbuf, const struct image_version *version)
{
    int ret = snprintf(vbuf, IMAGE_VERSION_STR_MAX, "%d.%d.%d",
                       version->major, version->minor, version->revision);


    if (ret > 0 && ret < (int) IMAGE_VERSION_STR_MAX && version->build_num) {
        snprintf(vbuf + ret , IMAGE_VERSION_STR_MAX - ret, "+%d", version->build_num);
    }
    vbuf[IMAGE_VERSION_STR_MAX - 1] = '\0';

    return 0;
}

int image_hash_to_str(char *hbuf, const uint8_t hash[32])
{
    hexlify(hash, 32, hbuf, IMAGE_HASH_STR_MAX);
    return 0;
}


#define MEMCPY_FLAG(_flag, _buf, _off, _len) \
    do { \
        const char flag[] = _flag ","; \
        memcpy(_buf + _off, flag, sizeof(flag)); \
        _off += (sizeof(flag) - 1); \
        _len -= (sizeof(flag) - 1); \
    } while (0)

int slot_flags_to_str(char *flags_buf, const struct mgmt_slot_state *slot)
{
    size_t flags_len = SLOT_FLAGS_STR_MAX;
    size_t flags_off = 0;

    if (slot->active) {
        MEMCPY_FLAG("active", flags_buf, flags_off, flags_len);
    }

    if (slot->confirmed) {
        MEMCPY_FLAG("confirmed", flags_buf, flags_off, flags_len);
    }

    if (slot->pending) {
        MEMCPY_FLAG("pending", flags_buf, flags_off, flags_len);
    }

    if (slot->permanent) {
        MEMCPY_FLAG("permanent", flags_buf, flags_off, flags_len);
    }

    if (flags_off) {
        flags_buf[flags_off - 1] = '\0';
    } else {
        flags_buf[0] = '\0';
    }
    return 0;
}

#undef MEMCPY_FLAG

void mcuboot_image_info_print(const struct mcuboot_image *image_info)
{
    char version_buf[IMAGE_VERSION_STR_MAX];
    char hash_buf[IMAGE_HASH_STR_MAX];

    image_version_to_str(version_buf, &image_info->version);
    image_hash_to_str(hash_buf, image_info->hash);

    printf("version:%s hash:%s size:%d\n", version_buf, hash_buf, image_info->img_sz);
}

void print_image_slot(struct mgmt_slot_state *slot)
{
    char version_buf[IMAGE_VERSION_STR_MAX];
    char hash_buf[IMAGE_HASH_STR_MAX];
    char flags[SLOT_FLAGS_STR_MAX];

    image_version_to_str(version_buf, &slot->version);
    image_hash_to_str(hash_buf, slot->hash);
    slot_flags_to_str(flags, slot);

    const char *bootable = slot->bootable ? "true" : "false";

    printf("slot:%d version:%s hash:%s bootable:%s flags:%s\n", slot->slot, version_buf, hash_buf, bootable, flags);
}


void print_image_slot_state(struct mgmt_image_state *slot_state)
{
    for (int slot_n = 0; slot_n < slot_state->num_slots; ++slot_n) {
        print_image_slot(&slot_state->slot[slot_n]);
    }
    if (slot_state->split_status) {
        printf("SplitStatus: %d\n", (int)slot_state->split_status);
    } else {
        printf("SplitStatus: N/A\n");
    }
}
