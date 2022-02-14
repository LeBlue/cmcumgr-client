/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#include "cbor.h"

#include "mgmt.h"
#include "mgmt_common.h"
#include "mgmt_hdr.h"
#include "mgmt_os.h"

ssize_t mgmt_create_os_echo_req(uint8_t *buf, size_t sz, const struct mgmt_echo_req *req)
{
	int rc;
	CborEncoder enc;
	CborEncoder map;
	struct mgmt_hdr *nh;
	int len;

	if (NULL == (nh = mgmt_header_init(buf, sz, MGMT_OP_WRITE, MGMT_GROUP_ID_OS, OS_MGMT_ID_ECHO))) {
		return -ENOBUFS;
	}

	mgmt_cbor_encoder_init(&enc, buf, sz);

	rc = cbor_encoder_create_map(&enc, &map, CborIndefiniteLength);

	rc |= cbor_encode_text_stringz(&map, "d");
	rc |= cbor_encode_text_stringz(&map, req->echo_str);

	rc |= cbor_encoder_close_container(&enc, &map);
	if (rc) {
		return -ENOBUFS;
	}

	len = mgmt_cbor_encoder_get_buffer_size(&enc, buf);

	mgmt_header_set_len(nh, len);

	return len + MGMT_HEADER_LEN;
}


int mgmt_os_echo_decode_rsp(const uint8_t *buf, size_t sz, struct mgmt_echo_rsp *rsp)
{
	int ret = mgmt_decode_err_rsp(buf, sz, &rsp->mgmt_rc);

    if (ret < 0 || (ret == 0 && rsp->mgmt_rc != 0)) {
		rsp->echo_str[0] = '\0';
        return ret;
    }

	rsp->mgmt_rc = 0;

	ret = mgmt_decode_rsp_single_stringz(buf, sz, "r", rsp->echo_str, sizeof(rsp->echo_str));

	if (ret <= 0) {
		return ret;
	}
	return -ENOMSG;
}


ssize_t mgmt_create_os_reset_req(uint8_t *buf, size_t sz)
{
	return mgmt_create_generic_no_data_req(buf, sz, MGMT_OP_WRITE, MGMT_GROUP_ID_OS, OS_MGMT_ID_RESET);
}

int mgmt_os_reset_decode_rsp(uint8_t *buf, size_t sz, struct mgmt_rc *rsp)
{
	int ret = mgmt_decode_err_rsp(buf, sz, &rsp->mgmt_rc);

	/* ret == 1: rc is not present in response */
	if (!ret || ret != 1) {
		return ret;
	}
	/* RC is only set on error, not on success. Set it in this case to success. */
	if (rsp->mgmt_rc < 0) {
		rsp->mgmt_rc = 0;
	}
	return 0;
}
