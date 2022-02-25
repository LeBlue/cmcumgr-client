/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "ptest/ptest.h"
#include "utils_test.h"

#include "mcumgr-client/mcumgr-client.h"

/* test internal API */
// #include "mgmt_hdr.h"

#define CBOR_BUF_SZ 512



static const uint8_t fw_data[20] = "0123456789" "0123456789";
static const uint8_t hash[32] = "0123456789ABCDEF" "0123456789ABCDEF";

/**
 * @brief Test image upload start packet is encoded correctly
 *
 */
static void test_encode_mgmt_img_upload_start(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));

    /*
    0000  02 00 00 44 00 01 00 01  bf 63 73 68 61 58 20 30  |...D.....cshaX 0|
    0016  31 32 33 34 35 36 37 38  39 61 62 63 64 65 66 30  |123456789ABCDEF0|
    0032  31 32 33 34 35 36 37 38  39 61 62 63 64 65 66 63  |123456789ABCDEFc|
    0048  6f 66 66 00 63 6c 65 6e  14 64 64 61 74 61 4c 30  |off.clen.ddataL0|
    0064  31 32 33 34 35 36 37 38  39 30 31 ff
    */
    const uint8_t msg[76] = "\x02\x00\x00\x44\x00\x01\x00\x01"
                            /* "\xbf\x63\x73\x68\x61\x58\x20\x30" */
                            "\xbf"
                                "cshaX" "\x20"
                                "0123456789ABCDEF" "0123456789ABCDEFc"
                                "off" "\x00"
                                "clen" "\x14"
                                "ddataL" "012345678901"
                            "\xff";

    size_t seglen = 12;

    cnt = mgmt_create_image_upload_seg0_req(buf, CBOR_BUF_SZ, sizeof(fw_data), fw_data, hash, seglen);

    /* hexdump(buf, cnt, "seq0\n"); */

    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt <= CBOR_BUF_SZ);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}


/**
 * @brief Test image upload continue packet is encoded correctly
 *
 */
static void test_encode_mgmt_img_upload_continue(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));

    /*
    0000  02 00 00 15 00 01 00 01  bf 63 6f 66 66 0c 64 64  |.........coff.dd|
    0016  61 74 61 48 30 31 32 33  34 35 36 37 ff           |ataH01234567.   |
    */
    const uint8_t msg[29] = "\x02\x00\x00\x15\x00\x01\x00\x01" "\xbf" "coff" "\x0c" "dd"
                            "ataH01234567" "\xff";
    size_t off = 12;
    size_t seglen = sizeof(fw_data) - off;

    cnt = mgmt_create_image_upload_segX_req(buf, CBOR_BUF_SZ, 12, fw_data, seglen);

    /* hexdump(buf, cnt, "seq0\n"); */

    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}


static void suite_mgmt_img_req_encode(void)
{
    const char *sn = "Suite Cbor encode image upload req";

    pt_add_test(test_encode_mgmt_img_upload_start, "Test encode IMG upload start", sn);
    pt_add_test(test_encode_mgmt_img_upload_continue, "Test encode IMG upload continue", sn);
}


int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_mgmt_img_req_encode);

    return pt_run();
}
