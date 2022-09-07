/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#include "ptest/ptest.h"

#include "mcuboot_img.h"
#include "file_reader_unix.h"

static const char test_bin_file[] = "mcuboot_image.bin";
static const char test_bin_file_trunc[] = "mcuboot_image_trunc_1.bin";

static const uint8_t hash[32] = "\xac\x35\x2c\x1f\x56\xad\xcb\x10\x29\x2d\xa6\xe1\xbe\x6d\x86\x72"
                                "\xac\xaa\x7b\x34\x32\x3a\x33\xb3\x5b\xdb\xa9\xaa\x25\x83\xc6\xe0";


static void test_img_parse_file(void)
{
    struct file_unix_handle fh;
    struct file_reader reader;
    struct mcuboot_image image_info;
    char *test_bin = pt_get_file_path(test_bin_file);

    int ret = file_unix_init(&reader, &fh, test_bin);

    PT_ASSERT(ret == 0);
    if (!ret) {
        ret = mcuboot_image_file_parse(&reader, &image_info);

        PT_ASSERT(ret == 0);
        PT_ASSERT(image_info.version.major == 1);
        PT_ASSERT(image_info.version.minor == 2);
        PT_ASSERT(image_info.version.revision == 345);
        PT_ASSERT(image_info.version.build_num == 67890);
        PT_ASSERT(image_info.img_sz == 16876);
        PT_ASSERT(image_info.file_sz == 17724);
        PT_ASSERT_MEM_EQ(hash, image_info.hash, 32);
    }
}

static void test_img_parse_file_truncated_1(void)
{
    struct file_unix_handle fh;
    struct file_reader reader;
    struct mcuboot_image image_info;
    char *test_bin_trunc = pt_get_file_path(test_bin_file_trunc);

    int ret = file_unix_init(&reader, &fh, test_bin_trunc);

    PT_ASSERT(ret == 0);
    if (!ret) {
        ret = mcuboot_image_file_parse(&reader, &image_info);

        PT_ASSERT(ret < 0);
    }
}

static void suite_img_parse_file(void)
{
    const char *sn = "Suite MCUboot image parsing";

    pt_add_test(test_img_parse_file, "Test MCUboot image parsing", sn);
    pt_add_test(test_img_parse_file_truncated_1, "Test MCUboot image parsing, truncated, fail", sn);
}


int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_set_prgpath(argv[0]);

    pt_add_suite(suite_img_parse_file);

    return pt_run();
}
