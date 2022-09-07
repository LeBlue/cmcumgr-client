/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#include "ptest/ptest.h"

#include "mcuboot_img.c"

static const uint8_t valid_header[32] = {
    0x3d, 0xb8, 0xf3, 0x96, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x04, 0x09, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t magic_swapped_header[32] = {
    0x96, 0xf3, 0xb8, 0x3d, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x04, 0x09, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


static void test_mcuboot_image_valid(void)
{
    const struct mcuboot_image_hdr *img_hdr = (struct mcuboot_image_hdr *) valid_header;

    PT_ASSERT(mcuboot_image_valid(img_hdr) == 1);
}


static void test_mcuboot_image_invalid(void)
{
    const struct mcuboot_image_hdr *img_hdr = (struct mcuboot_image_hdr *) magic_swapped_header;

    PT_ASSERT(mcuboot_image_valid(img_hdr) == 0);
}

static void test_img_parse_hdr_size(void)
{
    const struct mcuboot_image_hdr *img_hdr = (struct mcuboot_image_hdr *) valid_header;

    PT_ASSERT(mcuboot_image_get_image_size(img_hdr) == 67844);
}

static void test_img_parse_hdr_tlv_offset(void)
{
    const struct mcuboot_image_hdr *img_hdr = (struct mcuboot_image_hdr *) valid_header;

    PT_ASSERT(mcuboot_image_get_tlv_offset(img_hdr) == 68356);
}


static void test_img_parse_hdr_version(void)
{
    const struct mcuboot_image_hdr *img_hdr = (struct mcuboot_image_hdr *) valid_header;
    struct image_version version;
    mcuboot_image_get_version(img_hdr, &version);

    PT_ASSERT(version.major == 0);
    PT_ASSERT(version.minor == 0);
    PT_ASSERT(version.revision == 1);
    PT_ASSERT(version.build_num == 0);
}



static void suite_img_parse_header(void)
{
    const char *sn = "Suite MCUboot header";

    pt_add_test(test_mcuboot_image_valid, "Test parsing MCUboot image: header: magic valid", sn);
    pt_add_test(test_mcuboot_image_invalid, "Test parsing MCUboot image: header: magic invalid", sn);
    pt_add_test(test_img_parse_hdr_size, "Test parsing MCUboot image: header: img size", sn);
    pt_add_test(test_img_parse_hdr_tlv_offset, "Test parsing MCUboot image: header: tlv offset", sn);
    pt_add_test(test_img_parse_hdr_version, "Test parsing MCUboot image: header: version", sn);
}


int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_img_parse_header);

    return pt_run();
}
