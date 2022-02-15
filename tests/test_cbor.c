/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 *
 * All cbor test data was created with python cbor library 1.0.0.
 * The map length encoding is done by this library with a finite length.
 * The mcumgr implementation always encodes with infinite length and terminating
 * 'invalid' type and decodes both variants correctly.
 *
 * The tests mostly (sometimes both) use the infinite length encodeing of a map
 *
 */
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "ptest/ptest.h"
#include "utils_test.h"

#include "mcumgr.h"

/* test internal API */
#include "mgmt_hdr.h"

#define CBOR_BUF_SZ 512


static void test_mgmt_is_rsp_read(void)
{
    const uint8_t msg[8] = "\x01\x00\x00\x00\x00\x00\x00\x00";

    int ret = mgmt_header_is_rsp(msg, sizeof(msg));

    PT_ASSERT(ret == 1);
}


static void test_mgmt_is_rsp_write(void)
{
    const uint8_t msg[8] = "\x03\x00\x00\x00\x00\x00\x00\x00";

    int ret = mgmt_header_is_rsp(msg, sizeof(msg));

    PT_ASSERT(ret == 1);
}


static void test_mgmt_is_rsp_invalid(void)
{
    const uint8_t msg[8] = "\x00\x00\x00\x00\x00\x00\x00\x00";

    int ret = mgmt_header_is_rsp(msg, sizeof(msg));

    PT_ASSERT(ret == 0);
}


static void test_mgmt_header_is_rsp_complete(void)
{
    const uint8_t msg[8] = "\x02\x00\x00\x00\x00\x00\x00\x00";

    int ret = mgmt_header_is_rsp_complete(msg, sizeof(msg));

    PT_ASSERT(ret == 1);
}


static void test_mgmt_header_is_rsp_complete_fail_hdr(void)
{
    /* buffer to short for header */
    const uint8_t msg[7] = "\x02\x00\x00\x00\x00\x00\x00";

    int ret = mgmt_header_is_rsp_complete(msg, sizeof(msg));

    PT_ASSERT(ret == 0);
}


static void test_mgmt_header_is_rsp_complete_fail_data(void)
{
    /* buffer/data shorter than length in header */
    const uint8_t msg[10] = "\x02\x00\x00\x04\x00\x00\x00\x00" "12";

    int ret = mgmt_header_is_rsp_complete(msg, sizeof(msg));

    PT_ASSERT(ret == 0);
}


void suite_mgmt_rsp_basic_smp(void)
{
    const char *sn = "Suite Cbor parse SMP";
    pt_add_test(test_mgmt_is_rsp_read, "Test check is valid read response header", sn);
    pt_add_test(test_mgmt_is_rsp_write, "Test check is valid write response header write", sn);
    pt_add_test(test_mgmt_is_rsp_invalid, "Test check fail request header", sn);
    pt_add_test(test_mgmt_header_is_rsp_complete, "Test check fail request header, incomplete", sn);
    pt_add_test(test_mgmt_header_is_rsp_complete_fail_hdr, "Test check fail incomplete header", sn);
    pt_add_test(test_mgmt_header_is_rsp_complete_fail_data, "Test check fail incomplete data", sn);
}


static void test_mgmt_rsp_get_rc_too_short_buf(void)
{
    /* message with {"rc": 0} */
    const uint8_t msg[7] = "\x02\x00\x00\x06\x00\x00\x00";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == -ENODATA);
}


static void test_mgmt_rsp_get_rc_ok(void)
{
    /* message with {"rc": 0} */
    const uint8_t msg[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == 0);
    PT_ASSERT(mgmt_err == 0);
}

static void test_mgmt_rsp_get_rc_ok_alt_enc(void) {
    /* message with {"rc": 0}, alternate map encoding */
    const uint8_t msg[13] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\xa1" "brc" "\x00";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == 0);
    PT_ASSERT(mgmt_err == 0);
}


static void test_mgmt_rsp_get_rc_err(void)
{
    /* message with {"rc": 0} */
    const uint8_t msg[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x06\xff";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == 0);
    PT_ASSERT(mgmt_err == 6);
}


static void test_mgmt_rsp_get_rc_err_alt_enc(void)
{
    /* message with {"rc": 0}, alternate map encoding */
    const uint8_t msg[13] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\xa1" "brc" "\x06";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == 0);
    PT_ASSERT(mgmt_err == 6);
}


static void test_mgmt_rsp_get_rc_not_present_single_key(void)
{
    /* message with {"off": 0} */
    const uint8_t msg[14] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\xa1" "coff" "\x00";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == 1);
    PT_ASSERT(mgmt_err != 0);
}


static void test_mgmt_rsp_get_rc_not_present_2_keys(void)
{
    /* message with {"off": 0, "sha": b'\x00\x01' } */
    const uint8_t msg[21] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\xa2" "coff" "\x00" "cshaB" "\x00\x01";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == 1);
    PT_ASSERT(mgmt_err < 0);
}


static void test_mgmt_rsp_get_rc_not_present_2_keys_alt_enc(void)
{
    /* message with {"off": 0, "sha": b'\x00\x01' }, alternate encoding */
    const uint8_t msg[22] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\xbf" "coff" "\x00" "cshaB" "\x00\x01\xff";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == 1);
    PT_ASSERT(mgmt_err < 0);
}


static void test_mgmt_rsp_get_rc_invalid_map(void)
{
    /* invalid cbor data (no map) */
    const uint8_t msg[14] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\x80" "brc" "\x00";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == -ENOMSG);
    PT_ASSERT(mgmt_err < 0);
}


static void test_mgmt_rsp_get_rc_invalid_mapkey(void)
{
    /* invalid cbor data { "of": '\x00'} */
    const uint8_t msg[14] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\xa1" "boff" "\x00";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == -ENOMSG);
    PT_ASSERT(mgmt_err < 0);
}


static void test_mgmt_rsp_get_rc_invalid_mapkey_2(void)
{
    /* invalid cbor data { "of": '\x00'} */
    const uint8_t msg[14] = "\x02\x00\x00\x05\x00\x00\x00\x00" "\xa1" "Boff" "\x00";
    int64_t mgmt_err;

    int ret = mgmt_decode_err_rsp(msg, sizeof(msg), &mgmt_err);

    PT_ASSERT(ret == -ENOMSG);
    PT_ASSERT(mgmt_err < 0);
}


void suite_mgmt_rsp_common_rc(void)
{
    const char *sn = "Suite Cbor parse mgmt err";

    pt_add_test(test_mgmt_rsp_get_rc_too_short_buf, "Test parse mgmt error code, short buffer", sn);

    pt_add_test(test_mgmt_rsp_get_rc_ok, "Test parse mgmt error code OK", sn);
    pt_add_test(test_mgmt_rsp_get_rc_ok_alt_enc, "Test parse mgmt error code OK, alt. encoding", sn);
    pt_add_test(test_mgmt_rsp_get_rc_err, "Test parse mgmt error code 6", sn);
    pt_add_test(test_mgmt_rsp_get_rc_err_alt_enc, "Test parse mgmt error code 6, alt. encoding", sn);

    pt_add_test(test_mgmt_rsp_get_rc_not_present_single_key, "Test parse mgmt error code, not present single key", sn);
    pt_add_test(test_mgmt_rsp_get_rc_not_present_2_keys, "Test parse mgmt error code, not present, 2 keys", sn);
    pt_add_test(test_mgmt_rsp_get_rc_not_present_2_keys_alt_enc, "Test parse mgmt error code, not present, 2 keys, alt. encoding", sn);

    pt_add_test(test_mgmt_rsp_get_rc_invalid_map, "Test parse mgmt error code, invalid map encoding", sn);
    pt_add_test(test_mgmt_rsp_get_rc_invalid_mapkey, "Test parse mgmt error code, invalid value encoding", sn);
    pt_add_test(test_mgmt_rsp_get_rc_invalid_mapkey_2, "Test parse mgmt error code, invalid key encoding", sn);
}


/**
 * @brief Test OS echo packet is encoded correctly
 *
 */
static void test_encode_mgmt_os_echo(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));
    const uint8_t msg[18] = "\x02\x00\x00\x0a\x00\x00\x00\x00" "\xbf" "adeHallo" "\xff";
    struct mgmt_echo_req req = {
        .echo_str = "Hallo"
    };

    cnt = mgmt_create_os_echo_req(buf, CBOR_BUF_SZ, &req);

    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}


/**
 * @brief Test OS reset packet is encoded correctly
 *
 */
static void test_encode_mgmt_os_reset(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));
    const uint8_t msg[9] = "\x02\x00\x00\x01\x00\x00\x00\x05" "\xa0";

    cnt = mgmt_create_os_reset_req(buf, CBOR_BUF_SZ);

    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}


void suite_mgmt_os_encode(void) {
   pt_add_test(test_encode_mgmt_os_echo, "Test encode OS echo", "Suite Cbor encode mgmt");
   pt_add_test(test_encode_mgmt_os_reset, "Test encode OS reset", "Suite Cbor encode mgmt");
}


static void test_mgmt_os_echo_rsp_valid(void)
{
    /* cbor data { "r": "Hallo" } */
    const uint8_t msg[18] = "\x03\x00\x00\x0a\x00\x00\x00\x00" "\xbf" "areHallo" "\xff";
    struct mgmt_echo_rsp rsp;

    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == 0);
    PT_ASSERT_MEM_EQ("Hallo", rsp.echo_str, 5);
    PT_ASSERT(rsp.echo_str[5] == '\0');
}


static void test_mgmt_os_echo_rsp_valid_maxlen(void)
{
    /* zephyr limits resonses to 128 bytes echo string */
    /* cbor data { "r": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" "abcd" } */
    const uint8_t msg[142] = "\x03\x00\x00\x16\x00\x00\x00\x00" "\xbf" "arx" "\x80"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "abcd" "\xff";
    struct mgmt_echo_rsp rsp;

    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == 0);
    PT_ASSERT_MEM_EQ(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "abcd", rsp.echo_str, 128);
    PT_ASSERT(rsp.echo_str[128] == '\0');
}


static void test_mgmt_os_echo_rsp_valid_alt_enc(void)
{
    /* cbor data { "r": "Hallo" } */
    const uint8_t msg[17] = "\x03\x00\x00\x09\x00\x00\x00\x00" "\xa1" "areHallo";
    struct mgmt_echo_rsp rsp;

    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == 0);
    PT_ASSERT_MEM_EQ("Hallo", rsp.echo_str, 5);
    PT_ASSERT(rsp.echo_str[5] == '\0');
}


static void test_mgmt_os_echo_rsp_empty_str(void)
{
    /* cbor data { "r": "" } */
    const uint8_t msg[13] = "\x03\x00\x00\x05\x00\x00\x00\x00" "\xbf" "ar`" "\xff";

    struct mgmt_echo_rsp rsp;
    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == 0);
    PT_ASSERT_MEM_EQ("", rsp.echo_str, 0);
    PT_ASSERT(rsp.echo_str[0] == '\0');
}


static void test_mgmt_os_echo_rsp_missing_key(void)
{
    /* cbor data { "d": "" } */
    const uint8_t msg[13] = "\x03\x00\x00\x05\x00\x00\x00\x00" "\xbf" "ad`" "\xff";
    struct mgmt_echo_rsp rsp;

    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == -ENOMSG);
    PT_ASSERT(rsp.echo_str[0] == '\0');
}


static void test_mgmt_os_echo_rsp_wrong_value_type(void)
{
    /* cbor data { "r": 33 } */
    const uint8_t msg[14] = "\x03\x00\x00\x05\x00\x00\x00\x00" "\xbf" "ar" "\x18" "!" "\xff";
    struct mgmt_echo_rsp rsp;

    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == -ENOMSG);
    PT_ASSERT(rsp.echo_str[0] == '\0');
}


static void test_mgmt_os_echo_rsp_no_map(void)
{
    /* cbor data [] */
    const uint8_t msg[9] = "\x03\x00\x00\x01\x00\x00\x00\x00" "\x80";
    struct mgmt_echo_rsp rsp;

    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == -ENOMSG);
    PT_ASSERT(rsp.echo_str[0] == '\0');
}


static void test_mgmt_os_echo_rsp_msg_truncated(void)
{
    /* cbor data {"r" | (truncated) */
    const uint8_t msg[11] = "\x03\x00\x00\x05\x00\x00\x00\x00" "\xbf" "ar";
    struct mgmt_echo_rsp rsp;

    int ret = mgmt_os_echo_decode_rsp(msg, sizeof(msg), &rsp);

    PT_ASSERT(ret == -ENODATA);
    PT_ASSERT(rsp.echo_str[0] == '\0');
}



void suite_mgmt_os_parse_rsp(void)
{
    const char *sn = "Suite Cbor parse mgmt OS";

    pt_add_test(test_mgmt_os_echo_rsp_valid, "Test parse mgmt OS echo response", sn);
    pt_add_test(test_mgmt_os_echo_rsp_valid_alt_enc, "Test parse mgmt OS echo response, alt. encoding", sn);
    pt_add_test(test_mgmt_os_echo_rsp_valid_maxlen, "Test parse mgmt OS echo response, max len", sn);
    pt_add_test(test_mgmt_os_echo_rsp_empty_str, "Test parse mgmt OS echo response, empty string", sn);

    /* fail cases */
    pt_add_test(test_mgmt_os_echo_rsp_missing_key, "Test parse mgmt OS echo response, Fail missing key", sn);
    pt_add_test(test_mgmt_os_echo_rsp_wrong_value_type, "Test parse mgmt OS echo response, Fail wrong value type", sn);
    pt_add_test(test_mgmt_os_echo_rsp_no_map, "Test parse mgmt OS echo response, Fail no cbor map", sn);
    pt_add_test(test_mgmt_os_echo_rsp_msg_truncated, "Test parse mgmt OS echo response, Fail partial packet", sn);
}



/**
 * @brief Test image erase packet is encoded correctly
 *
 */
static void test_encode_mgmt_img_erase(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));
    const uint8_t msg[9] = "\x02\x00\x00\x01\x00\x01\x00\x05" "\xa0";

    cnt = mgmt_create_image_erase_req(buf, CBOR_BUF_SZ);

    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt <= CBOR_BUF_SZ);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}

static const uint8_t hash[32] = "0123456789ABCDEF" "0123456789ABCDEF";

static void test_encode_mgmt_img_state_get_list(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));

    const uint8_t msg[9] = "\x00\x00\x00\x01\x00\x01\x00\x00" "\xa0";

    cnt = mgmt_create_image_list_req(buf, CBOR_BUF_SZ);

    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}

static void test_encode_mgmt_img_state_set_test(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));

    const uint8_t msg[49] = "\x02\x00\x00\x29\x00\x01\x00\x00"
                            "\xbf" "dhashX" "\x20"
                            "0123456789ABCDEF" "0123456789ABCDEF"
                            "\xff";

    struct mgmt_image_test_req req;
    memcpy(req.fw_sha, hash, sizeof(hash));
    req.confirm = false;

    cnt = mgmt_create_image_test_req(buf, CBOR_BUF_SZ, &req);

    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}

static void test_encode_mgmt_img_state_set_test_confirm(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));

    const uint8_t msg[58] = "\x02\x00\x00\x32\x00\x01\x00\x00"
                            "\xbf"
                                "dhashX" "\x20"
                                "0123456789ABCDEF" "0123456789ABCDEF"
                                "gconfirm" "\xf5"
                            "\xff";

    struct mgmt_image_test_req req;
    memcpy(req.fw_sha, hash, sizeof(hash));
    req.confirm = true;

    cnt = mgmt_create_image_test_req(buf, CBOR_BUF_SZ, &req);

    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}

static void test_encode_mgmt_img_state_set_confirm(void)
{
    size_t cnt;
    uint8_t buf[CBOR_BUF_SZ + 1];
    memset(buf, 0, sizeof(buf));

    const uint8_t msg[19] = "\x02\x00\x00\x0b\x00\x01\x00\x00"
                            "\xbf" "gconfirm" "\xf5\xff";

    cnt = mgmt_create_image_confirm_req(buf, CBOR_BUF_SZ);

    PT_ASSERT_MEM_EQ(buf, msg, sizeof(msg));
    PT_ASSERT(cnt > 0);
    PT_ASSERT(cnt == sizeof(msg));
    PT_ASSERT((CBOR_BUF_SZ > cnt) || buf[cnt] == 0);
    PT_ASSERT(buf[CBOR_BUF_SZ] == 0);
}


void suite_mgmt_img_encode(void)
{
    const char *sn = "Suite Cbor encode mgmt image";

    pt_add_test(test_encode_mgmt_img_erase, "Test encode IMG reset", sn);

    pt_add_test(test_encode_mgmt_img_state_get_list, "Test encode IMG list", sn);
    pt_add_test(test_encode_mgmt_img_state_set_confirm, "Test encode IMG confirm", sn);
    pt_add_test(test_encode_mgmt_img_state_set_test, "Test encode IMG test", sn);
    pt_add_test(test_encode_mgmt_img_state_set_test_confirm, "Test encode IMG test and confirm", sn);

}


static void test_mgmt_parse_version_str(void)
{
    const char vbuf[] = "1.2.3";

    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);

    PT_ASSERT(ret == 0);
    PT_ASSERT(version.major == 1);
    PT_ASSERT(version.minor == 2);
    PT_ASSERT(version.revision == 3);
    PT_ASSERT(version.build_num == 0);
}

static void test_mgmt_parse_version_str_zero(void)
{
    const char vbuf[] = "1.0.3";

    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);

    PT_ASSERT(ret == 0);
    PT_ASSERT(version.major == 1);
    PT_ASSERT(version.minor == 0);
    PT_ASSERT(version.revision == 3);
    PT_ASSERT(version.build_num == 0);
}

static void test_mgmt_parse_version_str_multiple_digits(void)
{
    const char vbuf[] = "10.11.13";

    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);

    PT_ASSERT(ret == 0);
    PT_ASSERT(version.major == 10);
    PT_ASSERT(version.minor == 11);
    PT_ASSERT(version.revision == 13);
    PT_ASSERT(version.build_num == 0);
}


static void test_mgmt_parse_version_str_build_num(void)
{
    const char vbuf[] = "1.0.0+1400";

    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);

    PT_ASSERT(ret == 0);
    PT_ASSERT(version.major == 1);
    PT_ASSERT(version.minor == 0);
    PT_ASSERT(version.revision == 0);
    PT_ASSERT(version.build_num == 1400);
}


static void test_mgmt_parse_version_str_max(void)
{
    const char vbuf[] = "255.255.65535+4294967295";

    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);

    PT_ASSERT(ret == 0);
    PT_ASSERT(version.major == 255);
    PT_ASSERT(version.minor == 255);
    PT_ASSERT(version.revision == 65535);
    PT_ASSERT(version.build_num == 4294967295);
}


static void test_mgmt_parse_version_str_fail_fmt_maj(void)
{
    const char vbuf[] = "256.0.1";
    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);
    PT_ASSERT(ret == -EINVAL);
}

static void test_mgmt_parse_version_str_fail_fmt_min(void)
{
    const char vbuf[] = "0.256.1";
    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);
    PT_ASSERT(ret == -EINVAL);
}


static void test_mgmt_parse_version_str_fail_fmt_rev(void)
{
    const char vbuf[] = "0.1.65536";
    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);
    PT_ASSERT(ret == -EINVAL);
}

static void test_mgmt_parse_version_str_fail_fmt_build_num(void)
{
    const char vbuf[] = "0.1.1+4294967296";
    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);
    PT_ASSERT(ret == -EINVAL);
}


static void test_mgmt_parse_version_str_fail_fmt_early_plus(void)
{
    const char vbuf[] = "255+1";
    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);
    PT_ASSERT(ret == -EINVAL);
}


static void test_mgmt_parse_version_str_fail_fmt_all_dot(void)
{
    const char vbuf[] = "0.1.1.1";
    struct image_version version;
    int ret = mgmt_parse_version_string(vbuf, &version);
    PT_ASSERT(ret == -EINVAL);
}


// static void test_mgmt_parse_version_str_fail_fmt_leading_zero(void)
// {
//     const char vbuf[] = "0.1.01";
//     struct image_version version;
//     int ret = mgmt_parse_version_string(vbuf, &version);
//     PT_ASSERT(ret == -EINVAL);
// }


void suite_mgmt_img_parse_version(void)
{
    const char *sn = "Suite Cbor parse version string";

    pt_add_test(test_mgmt_parse_version_str, "Test version simple: OK", sn);

    pt_add_test(test_mgmt_parse_version_str_zero, "Test version w/ zeros: OK", sn);
    pt_add_test(test_mgmt_parse_version_str_multiple_digits, "Test version w/ multiple digits: OK", sn);
    pt_add_test(test_mgmt_parse_version_str_build_num, "Test version build num: OK", sn);
    pt_add_test(test_mgmt_parse_version_str_max, "Test version max: OK", sn);

    pt_add_test(test_mgmt_parse_version_str_fail_fmt_maj, "Test version: Format: Major overflow", sn);
    pt_add_test(test_mgmt_parse_version_str_fail_fmt_min, "Test version: Format: Minor overflow", sn);
    pt_add_test(test_mgmt_parse_version_str_fail_fmt_rev, "Test version: Format: Revision overflow", sn);
    pt_add_test(test_mgmt_parse_version_str_fail_fmt_build_num, "Test version: Format: Build Num overflow", sn);
    pt_add_test(test_mgmt_parse_version_str_fail_fmt_early_plus, "Test version: Format: Plus early", sn);
    pt_add_test(test_mgmt_parse_version_str_fail_fmt_all_dot, "Test version: Format: all dots", sn);
    // pt_add_test(test_mgmt_parse_version_str_fail_fmt_leading_zero, "Test version: Format: leading zero", sn);
}


static const uint8_t slot_state[] =
                            "\x01\x00\x00\xe3\x00\x01\x00\x00"
                            "\xa1"
                                "fimages" "\x82"
                                "\xa8"
                                    "dslot" "\x00"
                                    "gversione1.2.3"
                                    "dhashX " "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
                                        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
                                    "hbootable" "\xf5"
                                    "ipermanent" "\xf5"
                                    "iconfirmed" "\xf5"
                                    "factive" "\xf5"
                                    "gpending" "\xf4"
                                "\xa8"
                                    "dslot" "\x01"
                                    "gversione1.2.3"
                                    "dhashX " "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
                                        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
                                    "hbootable" "\xf5"
                                    "ipermanent" "\xf4"
                                    "iconfirmed" "\xf4"
                                    "factive" "\xf4"
                                    "gpending" "\xf4";

static void test_mgmt_img_state_parse(void)
{
    /* cbor data
     { "images": [
        { "slot": 0, "version": "1.2.3", "hash": hash, "bootable": True, "permanent": True, "confirmed":  True, "active": True, "pending": False  }
        { "slot": 1, "version": "1.2.3", "hash": hash, "bootable": True, "permanent": False, "confirmed": False, "active": False, "pending": False }
     }
     */
    struct mgmt_image_state_rsp rsp;

    int ret = mgmt_img_decode_list_rsp(slot_state, sizeof(slot_state) - 1, &rsp);

    PT_ASSERT(ret == 0);
    PT_ASSERT(rsp.mgmt_rc == 0);

    struct mgmt_slot_state *slot;
    slot = rsp.state.slot;
    PT_ASSERT(slot[0].slot == 0);
    PT_ASSERT(slot[0].version.major == 1);
    PT_ASSERT(slot[0].version.minor == 2);
    PT_ASSERT(slot[0].version.revision == 3);
    PT_ASSERT(slot[0].version.build_num == 0);
    PT_ASSERT(slot[0].bootable == 1);
    PT_ASSERT(slot[0].permanent == 1);
    PT_ASSERT(slot[0].confirmed == 1);
    PT_ASSERT(slot[0].active == 1);
    PT_ASSERT(slot[0].pending == 0);


    PT_ASSERT(slot[1].slot == 1);
    PT_ASSERT(slot[1].version.major == 1);
    PT_ASSERT(slot[1].version.minor == 2);
    PT_ASSERT(slot[1].version.revision == 3);
    PT_ASSERT(slot[1].version.build_num == 0);
    PT_ASSERT(slot[1].bootable == 1);
    PT_ASSERT(slot[1].permanent == 0);
    PT_ASSERT(slot[1].confirmed == 0);
    PT_ASSERT(slot[1].active == 0);
    PT_ASSERT(slot[1].pending == 0);
}

void suite_mgmt_img_parse_rsp(void)
{
    const char *sn = "Suite Cbor parse mgmt image";

    pt_add_test(test_mgmt_img_state_parse, "Test image state response", sn);
}


int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_mgmt_rsp_basic_smp);
    pt_add_suite(suite_mgmt_rsp_common_rc);
    pt_add_suite(suite_mgmt_os_encode);
    pt_add_suite(suite_mgmt_os_parse_rsp);
    pt_add_suite(suite_mgmt_img_encode);
    pt_add_suite(suite_mgmt_img_parse_version);
    pt_add_suite(suite_mgmt_img_parse_rsp);


    return pt_run();
}
