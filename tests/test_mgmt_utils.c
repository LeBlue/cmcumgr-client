/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <errno.h>

#include "ptest/ptest.h"
#include "utils_test.h"

#include "hexlify.h"
#include "mcumgr-client/mgmt_img.h"
#include "mcumgr-client/mgmt_utils.h"

static void test_slot_flags_active(void)
{
    /* test if buffer is long enough for every flag */
    char flags_buf[SLOT_FLAGS_STR_MAX];
    const struct mgmt_slot_state slot = {
        .active = 1,
        .confirmed = 1,
        .permanent = 1,
    };

    int ret = slot_flags_to_str(flags_buf, &slot);

    PT_ASSERT(ret == 0);
    PT_ASSERT_STR_EQ(flags_buf, "active,confirmed,permanent");
}


static void test_slot_flags_pending(void)
{
    /* test if buffer is long enough for every flag */
    char flags_buf[SLOT_FLAGS_STR_MAX];
    const struct mgmt_slot_state slot = {
        .pending = 1,
    };

    int ret = slot_flags_to_str(flags_buf, &slot);

    PT_ASSERT(ret == 0);
    PT_ASSERT_STR_EQ(flags_buf, "pending");
}


static void test_slot_flags_full(void)
{
    /* test if buffer is long enough for every flag */
    char flags_buf[SLOT_FLAGS_STR_MAX];
    const struct mgmt_slot_state slot = {
        .active = 1,
        .bootable = 1,
        .confirmed = 1,
        .pending = 1,
        .permanent = 1,
    };

    int ret = slot_flags_to_str(flags_buf, &slot);

    PT_ASSERT(ret == 0);
    PT_ASSERT_STR_EQ(flags_buf, "active,confirmed,pending,permanent");
}


void suite_mgmt_utils_functions(void)
{
    const char *sn = "Mgmt Utils Functions";
    pt_add_test(test_slot_flags_active, "Test slot flags printing: active", sn);
    pt_add_test(test_slot_flags_pending, "Test slot flags printing: pending", sn);
    pt_add_test(test_slot_flags_full, "Test slot flags printing: full", sn);

}


static const uint8_t hash[32] = "\xac\x35\x2c\x1f\x56\xad\xcb\x10\x29\x2d\xa6\xe1\xbe\x6d\x86\x72"
                                "\xac\xaa\x7b\x34\x32\x3a\x33\xb3\x5b\xdb\xa9\xaa\x25\x83\xc6\xe0";
static const char hash_str[] = "ac352c1f56adcb10292da6e1be6d8672"
                               "acaa7b34323a33b35bdba9aa2583c6e0";


static void test_image_parse_hash(void)
{
    uint8_t hash_buf[33];
    memset(hash_buf, 0, 33);

    int ret = unhexlify(hash_str, hash_buf, sizeof(hash_buf)-1); /* check for overflow */

    PT_ASSERT(ret == 32);
    PT_ASSERT_MEM_EQ(hash_buf, hash, 32);
    PT_ASSERT(hash_buf[32] == '\0');

}

static void test_image_parse_hash_short_buf(void)
{
    uint8_t hash_buf[33];
    memset(hash_buf, 0, 33);

    int ret = unhexlify(hash_str, hash_buf, sizeof(hash_buf)-2); /* check for overflow */

    PT_ASSERT(ret == 31);
    PT_ASSERT_MEM_EQ(hash_buf, hash, 31);
    PT_ASSERT(hash_buf[31] == '\0');
}

static void test_image_parse_hash_invalid_char_1(void)
{
    uint8_t hash_buf[3];
    const char *hash_string = "123G";
    memset(hash_buf, 0, 3);
    int ret = unhexlify(hash_string, hash_buf, sizeof(hash_buf)-1);
    PT_ASSERT(ret == -EINVAL);
}

static void test_image_parse_hash_invalid_char_2(void)
{
    uint8_t hash_buf[2];
    const char *hash_string = "g";
    int ret = unhexlify(hash_string, hash_buf, sizeof(hash_buf)-1);
    PT_ASSERT(ret == -EINVAL);
}

static void test_image_parse_hash_invalid_char_3(void)
{
    uint8_t hash_buf[2];
    const char *hash_string = ":";
    int ret = unhexlify(hash_string, hash_buf, sizeof(hash_buf)-1);
    PT_ASSERT(ret == -EINVAL);
}

static void test_image_parse_hash_invalid_char_4(void)
{
    uint8_t hash_buf[2];
    const char *hash_string = "/";
    int ret = unhexlify(hash_string, hash_buf, sizeof(hash_buf)-1);
    PT_ASSERT(ret == -EINVAL);
}

static void test_image_parse_hash_invalid_char_5(void)
{
    uint8_t hash_buf[2];
    const char *hash_string = "@";
    int ret = unhexlify(hash_string, hash_buf, sizeof(hash_buf)-1); /* check for overflow */
    PT_ASSERT(ret == -EINVAL);
}

static void test_image_parse_hash_invalid_char_6(void)
{
    uint8_t hash_buf[2];
    const char *hash_string = "`";
    int ret = unhexlify(hash_string, hash_buf, sizeof(hash_buf)-1); /* check for overflow */
    PT_ASSERT(ret == -EINVAL);
}


static void test_image_parse_hash_odd_len(void)
{
    uint8_t hash_buf[33];
    const char *hash_string = "123";
    memset(hash_buf, 0, 33);

    int ret = unhexlify(hash_string, hash_buf, sizeof(hash_buf)-1); /* check for overflow */
    PT_ASSERT(ret == -EINVAL);
}


static void test_image_print_hash(void)
{
    char str_buf[65];
    int ret = hexlify(hash, sizeof(hash), str_buf, sizeof(str_buf));

    PT_ASSERT(ret == 0);
    PT_ASSERT_MEM_EQ(str_buf, hash_str, 65); /* including \0 byte */
}

static void test_image_print_hash_short_buf(void)
{
    char str_buf[61];
    int ret = hexlify(hash, sizeof(hash), str_buf, sizeof(str_buf));

    PT_ASSERT(ret == -ENOBUFS);
    PT_ASSERT_MEM_EQ(str_buf, hash_str, 60);
    PT_ASSERT(str_buf[60] == 0); /* including \0 byte */
}

static void test_image_print_hash_no_null_bytes_space(void)
{
    char str_buf[64];
    int ret = hexlify(hash, sizeof(hash), str_buf, sizeof(str_buf));

    PT_ASSERT(ret == -ENOBUFS);
    /* should print hash as far as possible, but only full 2 digit hex */
    PT_ASSERT_MEM_EQ(str_buf, hash_str, 62);
    /* last should be null byte */
    PT_ASSERT(str_buf[62] == '\0'); /* including \0 byte */
}

static void suite_img_parse_utils(void)
{
    const char *sn = "Suite MCUboot image parsing utils";

    pt_add_test(test_image_parse_hash, "Test parse hash str to binary: OK", sn);
    pt_add_test(test_image_parse_hash_short_buf, "Test pring hash str to binary: OK", sn);
    pt_add_test(test_image_parse_hash_invalid_char_1, "Test pring hash str to binary: invalid char: Fail", sn);
    pt_add_test(test_image_parse_hash_invalid_char_2, "Test pring hash str to binary: invalid char: Fail", sn);
    pt_add_test(test_image_parse_hash_invalid_char_3, "Test pring hash str to binary: invalid char: Fail", sn);
    pt_add_test(test_image_parse_hash_invalid_char_4, "Test pring hash str to binary: invalid char: Fail", sn);
    pt_add_test(test_image_parse_hash_invalid_char_5, "Test pring hash str to binary: invalid char: Fail", sn);
    pt_add_test(test_image_parse_hash_invalid_char_6, "Test pring hash str to binary: invalid char: Fail", sn);
    pt_add_test(test_image_parse_hash_odd_len, "Test pring hash str to binary: odd # of chars: Fail", sn);


    pt_add_test(test_image_print_hash, "Test pring hash to string: OK", sn);
    pt_add_test(test_image_print_hash_short_buf, "Test pring hash to string: short buffer: -ENOBUFS", sn);
    pt_add_test(test_image_print_hash_no_null_bytes_space, "Test pring hash to string: no space for null byte: OK", sn);
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_mgmt_utils_functions);
    pt_add_suite(suite_img_parse_utils);

    return pt_run();
}
