/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <errno.h>

#include "cbor.h"
#include "mcumgr.h"
#include "mgmt_hdr.h"
#include "byteordering.h"

void mgmt_cbor_encoder_init(CborEncoder *enc, uint8_t *buf, size_t sz)
{
	cbor_encoder_init(enc, buf + MGMT_HEADER_LEN, sz - MGMT_HEADER_LEN, 0);
}

size_t mgmt_cbor_encoder_get_buffer_size(CborEncoder *enc, uint8_t *buf)
{
	return cbor_encoder_get_buffer_size(enc, buf + MGMT_HEADER_LEN);
}

/**
 * @brief Init cbor parser and find root map
 *
 * @param buf           buffer with cbor message
 * @param sz            size of @p buf
 * @param[out] parser   cbor parser to initialize, must not be NULL
 * @param[out] map_val  map container value, must not be NULL
 *
 * @retval              0 on success
 * @retval              -EINVAL failed to init cbor parser
 * @retval              -ENOMSG message does not contain root map
 */
int mgmt_cbor_parser_init(const uint8_t *buf, size_t sz, CborParser *parser, CborValue *map_val)
{
	int rc;
	rc = cbor_parser_init(buf, sz, 0, parser, map_val);
	if (rc) {
		return -EINVAL;
	}

	if (cbor_value_get_type(map_val) != CborMapType) {
		return -ENOMSG;
	}

	return 0;
}

/**
 * @brief Init cbor parser and enter the root map
 *
 * @param buf           buffer with cbor message
 * @param sz            size of @p buf
 * @param[out] parser   cbor parser to initialize, must not be NULL
 * @param[out] map_val  map container value, must not be NULL
 * @param[out] val      first value of map, must not be NULL
 *
 * @retval              0 on success
 * @retval              -EINVAL failed to init cbor parser
 * @retval              -ENOMSG failed to enter root map
 */
int mgmt_cbor_parser_init_enter_map(const uint8_t *buf, size_t sz, CborParser *parser, CborValue *map_val, CborValue *val)
{
	int rc;
	rc = mgmt_cbor_parser_init(buf, sz, parser, map_val);
	if (rc) {
		return rc;
	}

	if (cbor_value_enter_container(map_val, val)) {
		return -ENOMSG;
	}
	return 0;
}



size_t mgmt_create_generic_no_data_req(uint8_t *buf, size_t sz, uint8_t op, uint16_t group, uint8_t id)
{
	struct mgmt_hdr *nh;

	if (NULL == (nh = mgmt_header_init(buf, sz, op, group, id))) {
		return -ENOBUFS;
	}

	if (sz < MGMT_HEADER_LEN + 1) {
		return -ENOBUFS;
	}

	/* empty map */
	buf[MGMT_HEADER_LEN] = CborMapType;
	mgmt_header_set_len(nh, 1);

	return MGMT_HEADER_LEN + 1;
}



/**
 * @brief decode a single int64_t value from SMP management packet
 *
 * @param buf start of SMP packet, must not be NULL
 * @param sz size of supplied buffer @p buf
 * @param keyname the key to search in the SMP payload, must not be NULL
 * @param retval returns the value of the key, valid only if 0 was returned, must not be NULL
 *
 * @retval 0 Successful execution, @p retval is valid
 * @retval 1 SMP packet was parsed without errors, but the @p keyname was not found
 * @retval -EINVAL Argument validation failed, @p buf too short.
 * @retval -ENODATA @p buf too short to hold SMP header or not a complete SMP packet.
 * @retval -ENOMSG SMP payload decoding error or unexpected format, e.g. not a map, requested value has wrong format, ...
 */
int mgmt_decode_rsp_single_int64(const uint8_t *buf, size_t sz, const char* keyname, int64_t *retval)
{
	CborParser parser;
	CborValue map_val;
	CborValue val;
	int rc;
	int64_t val64;
	CborType vt;

	if (!keyname) {
		return -EINVAL;
	}

	rc = mgmt_header_len_check_and_advance(&buf, &sz);
	if (rc) {
		return rc;
	}

	rc = mgmt_cbor_parser_init(buf, sz, &parser, &map_val);
	if (rc) {
		return rc;
	}

	rc = cbor_value_map_find_value(&map_val, keyname, &val);
	if (rc) {
		return -ENOMSG;
	}

	vt = cbor_value_get_type(&val);

	/* message was OK, but key was not found */
	if (vt == CborInvalidType) {
		return 1;
	}

	if (vt == CborIntegerType) {
		if (cbor_value_get_int64(&val, &val64)) {
			return -ENOMSG;
		}
		*retval = val64;
		return 0;
	}
	return -ENOMSG;
}


/**
 * @brief decode a single string value from SMP management packet
 *
 * @param buf start of SMP packet, must not be NULL
 * @param sz size of supplied buffer @p buf
 * @param keyname the key to search in the SMP payload, must not be NULL
 * @param str returns the string value of the key, valid only if 0 was returned, must not be NULL
 * @param strsz size of buffer provided in @p str
 *
 * @retval 0 Successful execution, @p retval is valid.
 * @retval 1 SMP packet was parsed without errors, but the @p keyname was not found
 * @retval -EINVAL Argument validation failed, @p buf too short.
 * @retval -ENODATA @p buf too short to hold SMP header or not a complete SMP packet.
 * @retval -ENOMSG SMP payload decoding error or unexpected format, e.g. not a map, requested value has wrong format, ...
 */
int mgmt_decode_rsp_single_stringz(const uint8_t *buf, size_t sz, const char* keyname, char *str, size_t strsz)
{
	CborParser parser;
	CborValue map_val;
	CborValue val;
	int rc;
	CborType vt;

	str[0] = '\0';

	rc = mgmt_header_len_check_and_advance(&buf, &sz);
	if (rc) {
		return rc;
	}

	rc = mgmt_cbor_parser_init(buf, sz, &parser, &map_val);
	if (rc) {
		return rc;
	}

	rc = cbor_value_map_find_value(&map_val, keyname, &val);
	if (rc) {
		return -ENOMSG;
	}

	vt = cbor_value_get_type(&val);

	/* message was OK, but key was not found */
	if (vt == CborInvalidType) {
		return 1;
	}

	if (vt == CborTextStringType) {
		size_t nlen = strsz;
		rc = cbor_value_copy_text_string(&val, str, &nlen, &val);
		if (rc == CborErrorOutOfMemory) {
			/* truncate string */
			str[strsz - 1] = '\0';
			return -ENOMEM;
		} else if (rc) {
			return -ENOMSG;
		}
		return 0;
	}

	/* wrong value type */
	return -ENOMSG;
}

/**
 * @brief Check and return the mgmt return code from an SMP message
 *
 * @param buf       The buffer holding the message
 * @param sz        Size of the buffer
 * @param mgmt_err  pointer where to save the mgmt return code
 * @return          0 on success and error code otherwise
 *
 * @retval 0 Successful execution, @p retval is valid.
 * @retval 1 SMP packet was parsed without errors, but the mgmt return code was not found in the message
 * @retval -EINVAL Argument validation failed
 * @retval -ENODATA @p buf too short to hold SMP header or not a complete SMP packet.
 * @retval -ENOMSG SMP payload decoding error or unexpected format, e.g. not a map, requested value has wrong format, ...
 */
int mgmt_decode_err_rsp(const uint8_t *buf, size_t sz, int64_t *mgmt_err)
{
	/* do not pass accidentally 0 back */
	*mgmt_err = -1;

	return mgmt_decode_rsp_single_int64(buf, sz, "rc", mgmt_err);
}
