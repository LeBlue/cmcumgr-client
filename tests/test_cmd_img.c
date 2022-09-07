/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "ptest/ptest.h"
#include "mock_transport.h"

#include "smp_transport.h"

#define MOCK_BUF_SZ 2048
#define MAX_CHUNKS 20

#include "mcumgr-client.h"

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


static void test_cmd_img_list(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    mock_transport_add_response(t, slot_state, sizeof(slot_state));

    rc = cmd_img_run_image_list(t, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == 0);
}


static void test_cmd_img_list_not_supported(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    uint8_t rsp_buf[14] = "\x01\x00\x00\x06\x00\x01\x00\x00" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_list(t, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == MGMT_ERR_ENOTSUP);
}

static void test_cmd_img_list_timeout(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    /* do not add data response */

    rc = cmd_img_run_image_list(t, &rsp);

    PT_ASSERT(rc == -ETIMEDOUT);
}

static void test_cmd_img_list_wrong_group_id(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    uint8_t rsp_buf[14] = "\x01\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_list(t, &rsp);

    PT_ASSERT(rc == -EPROTO);
}


static void test_cmd_img_list_wrong_cmd_id(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    uint8_t rsp_buf[14] = "\x01\x00\x00\x06\x00\x00\x00\x01" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_list(t, &rsp);

    PT_ASSERT(rc == -EPROTO);
}

static void suite_cmd_img_state(void)
{
    const char *sn =  "Suite CMD execution IMG list";

    pt_add_test(test_cmd_img_list, "Test Command IMG List", sn);
    pt_add_test(test_cmd_img_list_not_supported, "Test Command IMG List: not supported", sn);
    pt_add_test(test_cmd_img_list_timeout, "Test Command IMG List: timeout", sn);
    pt_add_test(test_cmd_img_list_wrong_group_id, "Test Command IMG List: wrong group id rsp", sn);
    pt_add_test(test_cmd_img_list_wrong_cmd_id, "Test Command IMG List: wrong cmd id rsp", sn);
}

static void test_cmd_img_test(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;
    struct mgmt_image_test_req req = {0};

    mock_transport_add_response(t, slot_state, sizeof(slot_state));

    rc = cmd_img_run_image_test(t, &req, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == 0);
}


static void test_cmd_img_test_not_supported(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;
    struct mgmt_image_test_req req = {0};

    uint8_t rsp_buf[14] = "\x01\x00\x00\x06\x00\x01\x00\x00" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_test(t, &req, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == MGMT_ERR_ENOTSUP);
}

static void test_cmd_img_test_timeout(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;
    struct mgmt_image_test_req req = {0};

    /* do not add data response */

    rc = cmd_img_run_image_test(t, &req, &rsp);

    PT_ASSERT(rc == -ETIMEDOUT);
}

static void test_cmd_img_test_wrong_group_id(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;
    struct mgmt_image_test_req req = {0};

    uint8_t rsp_buf[14] = "\x01\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_test(t, &req, &rsp);

    PT_ASSERT(rc == -EPROTO);
}


static void test_cmd_img_test_wrong_cmd_id(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;
    struct mgmt_image_test_req req = {0};

    uint8_t rsp_buf[14] = "\x01\x00\x00\x06\x00\x00\x00\x01" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_test(t, &req, &rsp);

    PT_ASSERT(rc == -EPROTO);
}


static void suite_cmd_img_test(void)
{
    const char *sn =  "Suite CMD execution IMG test";

    pt_add_test(test_cmd_img_test, "Test Command IMG Test", sn);
    pt_add_test(test_cmd_img_test_not_supported, "Test Command IMG Test: not supported", sn);
    pt_add_test(test_cmd_img_test_timeout, "Test Command IMG Test: timeout", sn);
    pt_add_test(test_cmd_img_test_wrong_group_id, "Test Command IMG Test: wrong group id rsp", sn);
    pt_add_test(test_cmd_img_test_wrong_cmd_id, "Test Command IMG Test: wrong cmd id rsp", sn);
}


static void test_cmd_img_confirm(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    mock_transport_add_response(t, slot_state, sizeof(slot_state));

    rc = cmd_img_run_image_confirm(t, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == 0);
}


static void test_cmd_img_confirm_not_supported(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    uint8_t rsp_buf[14] = "\x01\x00\x00\x06\x00\x01\x00\x00" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_confirm(t, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == MGMT_ERR_ENOTSUP);
}

static void test_cmd_img_confirm_timeout(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    /* do not add data response */

    rc = cmd_img_run_image_confirm(t, &rsp);

    PT_ASSERT(rc == -ETIMEDOUT);
}

static void test_cmd_img_confirm_wrong_group_id(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    uint8_t rsp_buf[14] = "\x03\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_confirm(t, &rsp);

    PT_ASSERT(rc == -EPROTO);
}


static void test_cmd_img_confirm_wrong_cmd_id(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_image_state_rsp rsp;

    uint8_t rsp_buf[14] = "\x03\x00\x00\x06\x00\x00\x00\x01" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_img_run_image_confirm(t, &rsp);

    PT_ASSERT(rc == -EPROTO);
}

static void suite_cmd_img_confirm(void)
{
    const char *sn =  "Suite CMD execution IMG confirm";

    pt_add_test(test_cmd_img_confirm, "Test Command IMG Confirm", sn);
    pt_add_test(test_cmd_img_confirm_not_supported, "Test Command IMG Confirm: not supported", sn);
    pt_add_test(test_cmd_img_confirm_timeout, "Test Command IMG Confirm: timeout", sn);
    pt_add_test(test_cmd_img_confirm_wrong_group_id, "Test Command IMG Confirm: wrong group id rsp", sn);
    pt_add_test(test_cmd_img_confirm_wrong_cmd_id, "Test Command IMG Confirm: wrong cmd id rsp", sn);
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_cmd_img_state);
    pt_add_suite(suite_cmd_img_test);
    pt_add_suite(suite_cmd_img_confirm);

    return pt_run();
}
