/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#include "ptest/ptest.h"
#include "utils_test.h"
#include "mcuboot_img.h"
#include "file_reader_unix.h"

static const char test_bin[] = "mcuboot_image.bin";

static const uint8_t hash[32] = "\xac\x35\x2c\x1f\x56\xad\xcb\x10\x29\x2d\xa6\xe1\xbe\x6d\x86\x72"
                                "\xac\xaa\x7b\x34\x32\x3a\x33\xb3\x5b\xdb\xa9\xaa\x25\x83\xc6\xe0";


void test_img_parse_file(void)
{
    struct file_unix_handle fh;
    struct file_reader reader;
    struct mcuboot_image image_info;

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
        PT_ASSERT_MEM_EQ(hash, image_info.hash, 32);

    }
}

void suite_img_parse_file(void)
{
    const char *sn = "Suite MCUboot image parsing";

    pt_add_test(test_img_parse_file, "Test MCUboot image parsing", sn);
}


int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_img_parse_file);

    return pt_run();
}