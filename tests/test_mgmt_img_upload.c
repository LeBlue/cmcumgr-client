/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "ptest/ptest.h"

#include "mcumgr-client.h"

#define CBOR_BUF_SZ MGMT_MAX_MTU


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


static void test_mgmt_img_upload_parse_rsp_ok(void)
{
    int ret;
    const uint8_t rsp[19] = "\x03\x00\x00\x0b\x00\x01\x00\x01" "\xa2" "brc" "\x00" "coff" "\x18" "x";
    struct mgmt_rc err = {0};
    size_t off;

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == 0);
    PT_ASSERT(err.mgmt_rc == 0);
    PT_ASSERT(off == 120);
}

static void test_mgmt_img_upload_parse_rsp_ok_mgmt_err(void)
{
    int ret;
    const uint8_t rsp[13] = "\x03\x00\x00\x05\x00\x01\x00\x01" "\xa2" "brc" "\x01";
    struct mgmt_rc err = {0};
    size_t off = (size_t) -10;

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == 0);
    PT_ASSERT(err.mgmt_rc == 1);
    PT_ASSERT(off == (size_t)-10);
}


static void test_mgmt_img_upload_parse_rsp_trunc(void)
{
    int ret;
    const uint8_t rsp[18] = "\x03\x00\x00\x0a\x00\x01\x00\x01" "\xa2" "brc" "\x00" "coff" "\x18";
    struct mgmt_rc err = {0};
    size_t off = 0;

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == -ENOMSG);
}


static void test_mgmt_img_upload_parse_rsp_trunc_2(void)
{
    int ret;
    const uint8_t rsp[18] = "\x03\x00\x00\x0b\x00\x01\x00\x01" "\xa2" "brc" "\x00" "coff" "\x18";
    struct mgmt_rc err = {0};
    size_t off = 0;

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == -ENODATA);
}


static void test_mgmt_img_upload_parse_rsp_trunc_hdr(void)
{
    int ret;
    const uint8_t rsp[7] = "\x03\x00\x00\x0a\x00\x01\x00";
    struct mgmt_rc err = {0};
    size_t off = 0;

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == -ENODATA);
}

static void test_mgmt_img_upload_parse_rsp_missing_off(void)
{
    int ret;
    struct mgmt_rc err = {0};
    size_t off;
    const uint8_t rsp[13] = "\x03\x00\x00\x05\x00\x01\x00\x01" "\xa2" "brc" "\x00";

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == -ENOMSG);
}

static void test_mgmt_img_upload_parse_rsp_missing_rc(void)
{
    int ret;
    const uint8_t rsp[14] = "\x03\x00\x00\x06\x00\x01\x00\x01" "\xa2" "coff" "\x18";
    struct mgmt_rc err = {0};
    size_t off;

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == -ENOMSG);
}

static void test_mgmt_img_upload_parse_rsp_invalid_args(void)
{
    int ret;
    const uint8_t rsp[19] = "\x03\x00\x00\x0b\x00\x01\x00\x01" "\xa2" "brc" "\x00" "coff" "\x18" "x";
    struct mgmt_rc err = {0};
    size_t off;

    ret = mgmt_img_upload_decode_rsp(NULL, sizeof(rsp), &off, &err);
    PT_ASSERT(ret == -EINVAL);

    ret = mgmt_img_upload_decode_rsp(rsp, 0, &off, &err);
    PT_ASSERT(ret == -ENODATA); /* not techically invalid, is zero length data */

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), NULL, &err);
    PT_ASSERT(ret == -EINVAL);

    ret = mgmt_img_upload_decode_rsp(rsp, sizeof(rsp), &off, NULL);
    PT_ASSERT(ret == -EINVAL);
}


static void suite_mgmt_img_rsp_parse(void)
{
    const char *sn = "Suite Cbor parse image upload rsp";

    pt_add_test(test_mgmt_img_upload_parse_rsp_ok, "Test parse IMG upload OK", sn);
    pt_add_test(test_mgmt_img_upload_parse_rsp_ok_mgmt_err, "Test parse IMG upload OK: mgmt err", sn);
    pt_add_test(test_mgmt_img_upload_parse_rsp_trunc, "Test parse IMG upload truncated", sn);
    pt_add_test(test_mgmt_img_upload_parse_rsp_trunc_2, "Test parse IMG upload truncated 2", sn);
    pt_add_test(test_mgmt_img_upload_parse_rsp_trunc_hdr, "Test parse IMG upload truncated header", sn);
    pt_add_test(test_mgmt_img_upload_parse_rsp_missing_off, "Test parse IMG upload missing 'offset'", sn);
    pt_add_test(test_mgmt_img_upload_parse_rsp_missing_rc, "Test parse IMG upload missing 'rc'", sn);
    pt_add_test(test_mgmt_img_upload_parse_rsp_invalid_args, "Test parse IMG upload: invalid fn arguments", sn);
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_mgmt_img_req_encode);
    pt_add_suite(suite_mgmt_img_rsp_parse);

    return pt_run();
}
