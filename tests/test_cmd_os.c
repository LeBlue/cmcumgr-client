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
#include "utils_test.h"
#include "mock_transport.h"

#include "smp_transport.h"

#define MOCK_BUF_SZ 2048
#define MAX_CHUNKS 20


#include "cmd_os.h"
#include "cmd_img.h"
#include "mcumgr.h"

void test_cmd_os_reset(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_rc rsp;
    uint8_t rsp_buf[14] = "\x03\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_os_run_reset(t, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == 0);
}

void test_cmd_os_reset_not_supported(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_rc rsp;
    uint8_t rsp_buf[14] = "\x03\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x08\xff";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_os_run_reset(t, &rsp);

    PT_ASSERT(rc == 0);
    PT_ASSERT(rsp.mgmt_rc == MGMT_ERR_ENOTSUP);
}

void test_cmd_os_reset_timeout(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_rc rsp;
    /* do not add data response */

    rc = cmd_os_run_reset(t, &rsp);

    PT_ASSERT(rc == -ETIMEDOUT);
}

void test_cmd_os_reset_trunc_rsp(void)
{
    int rc;
    struct smp_transport *t = setup_smp_mock();
    struct mgmt_rc rsp;
    uint8_t rsp_buf[8] = "\x03\x00\x00\x06\x00\x00\x00\x00";

    mock_transport_add_response(t, rsp_buf, sizeof(rsp_buf));

    rc = cmd_os_run_reset(t, &rsp);

    PT_ASSERT(rc == -ENODATA);
    PT_ASSERT(rsp.mgmt_rc < 0);
}


void suite_cmd_os_reset(void)
{
    const char *sn =  "Suite Command OS execution";

    pt_add_test(test_cmd_os_reset, "Test Command OS Reset: OK", sn);
    pt_add_test(test_cmd_os_reset_not_supported, "Test Command OS Reset: RC: not supported", sn);
    pt_add_test(test_cmd_os_reset_timeout, "Test Command OS Reset: timeout", sn);
    pt_add_test(test_cmd_os_reset_trunc_rsp, "Test Command OS Reset: truncated response", sn);
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_cmd_os_reset);

    return pt_run();
}
