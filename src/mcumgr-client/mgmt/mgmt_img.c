/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#include "cbor.h"

#include "mgmt_common.h"
#include "mgmt.h"
#include "mgmt_hdr.h"
#include "mgmt_img.h"



#define PRDBG 0
#if PRDBG
#include <stdio.h>
#define DBG(fmt, args...) do { fprintf(stderr, "dbg: " fmt, ##args); } while (0)
#else
#define DBG(fmt, args...) do {} while (0)
#endif

/**
 * @brief stack buffer length for cbor map key decoding
 *
 * Following keys are expected, add one for \0:
 *
 * - rc
 * - r
 * - d
 * - sha
 * - off
 * - data
 * - len
 * - confirm
 * - images
 * - version
 * - hash
 * - confirmed
 * - bootable
 * - permanent
 * - pending
 * - active
 * - splitStatus
 *
 */
#define MGMT_CBOR_MAX_KEYLEN 12




ssize_t mgmt_create_image_list_req(uint8_t *buf, size_t sz)
{
	return mgmt_create_generic_no_data_req(buf, sz, MGMT_OP_READ, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_STATE);
}

ssize_t mgmt_create_image_erase_req(uint8_t *buf, size_t sz)
{
	return mgmt_create_generic_no_data_req(buf, sz, MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_ERASE);
}

ssize_t mgmt_create_image_confirm_req(uint8_t *buf, size_t sz)
{
	int rc;
	CborEncoder enc;
	CborEncoder map;
	struct mgmt_hdr *nh;
	int len;

	if (NULL == (nh = mgmt_header_init(buf, sz, MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_STATE))) {
		return -ENOBUFS;
	}

	mgmt_cbor_encoder_init(&enc, buf, sz);

	rc = cbor_encoder_create_map(&enc, &map, CborIndefiniteLength);
	rc |= cbor_encode_text_stringz(&map, "confirm");
	rc |= cbor_encode_boolean(&map, true);

	rc |= cbor_encoder_close_container(&enc, &map);
	if (rc) {
		return -ENOBUFS;
	}

	len = mgmt_cbor_encoder_get_buffer_size(&enc, buf);
	mgmt_header_set_len(nh, len);

	return len + MGMT_HEADER_LEN;
}

ssize_t mgmt_create_image_test_req(uint8_t *buf, size_t sz, struct mgmt_image_test_req *req)
{
	int rc;
	CborEncoder enc;
	CborEncoder map;
	struct mgmt_hdr *nh;
	int len;

	if (NULL == (nh = mgmt_header_init(buf, sz, MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_STATE))) {
		return -ENOBUFS;
	}

	mgmt_cbor_encoder_init(&enc, buf, sz);

	rc = cbor_encoder_create_map(&enc, &map, CborIndefiniteLength);
	rc |= cbor_encode_text_stringz(&map, "hash");
	rc |= cbor_encode_byte_string(&map, req->fw_sha, 32);

	if (req->confirm) {
		rc |= cbor_encode_text_stringz(&map, "confirm");
		rc |= cbor_encode_boolean(&map, req->confirm);
	}

	rc |= cbor_encoder_close_container(&enc, &map);
	if (rc) {
		return -ENOBUFS;
	}

	len = mgmt_cbor_encoder_get_buffer_size(&enc, buf);
	mgmt_header_set_len(nh, len);

	return len + MGMT_HEADER_LEN;
}


int mgmt_parse_version_string(const char *vbuf, struct image_version *version)
{
	int i = 0;

	memset(version, 0, sizeof(*version));

	for (i = 0; i < 4; ++i) {
		uint64_t sum = 0;
		while (*vbuf >= '0' && *vbuf <= '9') {
			sum *= 10;
			sum += *vbuf - '0';

			if (sum > (UINT64_MAX)) return -EINVAL;
			++vbuf;
		}

		switch (i) {
			case 0:
				if (sum > UINT8_MAX) return -EINVAL;
				version->major = sum;
				break;
			case 1:
				if (sum > UINT8_MAX) return -EINVAL;
				version->minor = sum;
				break;
			case 2:
				if (sum > UINT16_MAX) return -EINVAL;
				version->revision = sum;
				break;
			case 3:
				if (sum > UINT32_MAX) return -EINVAL;
				version->build_num = sum;
				break;
			default:
				break;
		}

		switch (*vbuf) {
			case '\0':
				return 0;
			case '.':
				if (i >= 3) {
					return -EINVAL;
				}
				break;
			case '+':
				if (i != 2) {
					return -EINVAL;
				}
				break;
			default:
				return -EINVAL;
		}

		++vbuf;
	}
	if (*vbuf != '\0') {
		return -EINVAL;
	}
	return 0;
}

/**
 * @brief parse cbor map as image slot
 *
 * @param map_val  a valid slot cbor map
 * @param slot     a valid slot object
 *
 * @retval         0 success
 * @retval   -ENOMSG parsing failed. Invalid message format.
 */
static int mgmt_img_parse_slot(CborValue *map_val, struct mgmt_slot_state *slot)
{
	CborValue val;
	/* required fields */
	bool found_slot = false, found_hash = false, found_version = false;
	struct {
		const char* key;
		uint8_t *const flag;
		const bool required;
		bool found;
	} flags_def[5] = {
		{ .key = "bootable", .flag = &slot->bootable, .required = true, .found = false },
		{ .key = "confirmed", .flag = &slot->confirmed, .required = true, .found = false },
		{ .key = "pending", .flag = &slot->pending, .required = true, .found = false },
		{ .key = "active", .flag = &slot->active, .required = true, .found = false },
		{ .key = "permanent", .flag = &slot->permanent, .required = true, .found = false },
	};

	DBG("Enter slot\n");

	if (cbor_value_enter_container(map_val, &val)) {
		return -ENOMSG;
	}

	while (!cbor_value_at_end(&val)) {
		DBG("Iterate key-val\n");

		if (cbor_value_get_type(&val) != CborTextStringType) {
			DBG("Key not a string\n");
			break;
		}

		/* ignore unknown keys */
		bool result;
		if (cbor_value_text_string_equals(&val, "slot", &result)) {
			goto leave;
		}
		if (result) {
			DBG("key 'slot'\n");
			cbor_value_advance(&val);

			CborType vt = cbor_value_get_type(&val);
			if (vt != CborIntegerType) {
				goto leave;
			} else {
				int64_t v;

				cbor_value_get_int64(&val, &v);
				slot->slot = v;
				cbor_value_advance(&val);
				DBG("Slot: %ld\n", v);
				found_slot = true;
				continue;
			}
		}
		if (cbor_value_text_string_equals(&val, "version", &result)) {
			goto leave;
		}
		if (result) {
			cbor_value_advance(&val);
			DBG("key 'version'\n");

			if (cbor_value_get_type(&val) != CborTextStringType) {
				goto leave;
			} else {
				char version_buf[25];
				size_t nlen = sizeof(version_buf) - 1;
				if (cbor_value_copy_text_string(&val, version_buf, &nlen, &val))
				{
					goto leave;
				}
				version_buf[24] = '\0';
				DBG("%s\n", version_buf);
				if (mgmt_parse_version_string(version_buf, &slot->version)) {
					goto leave;
				}
				found_version = true;
				continue;
			}
		}

		if (cbor_value_text_string_equals(&val, "hash", &result)) {
			goto leave;
		}
		if (result) {
			cbor_value_advance(&val);
			DBG("key 'hash'\n");

			if (cbor_value_get_type(&val) != CborByteStringType) {
				goto leave;
			} else {
				size_t nlen = sizeof(slot->hash);
				if (cbor_value_copy_byte_string(&val, slot->hash, &nlen, &val))
				{
					goto leave;
				}
				found_hash = true;
				continue;
			}
		}

		for (size_t i = 0; i < (sizeof(flags_def)/sizeof(flags_def[0])); ++i) {
			if (cbor_value_get_type(&val) != CborTextStringType) {
				goto leave;
			}

			if (cbor_value_text_string_equals(&val, flags_def[i].key, &result)) {
				goto leave;
			}
			if (result) {
				cbor_value_advance(&val);
				if (cbor_value_get_type(&val) != CborBooleanType) {
					goto leave;
				} else {
					bool bool_val;
					if (cbor_value_get_boolean(&val, &bool_val))
					{
						goto leave;
					}
					*(flags_def[i].flag) = !!bool_val;
					flags_def[i].found = true;
					DBG("%s: %d\n", flags_def[i].key, *(flags_def[i].flag));

					cbor_value_advance(&val);
					break;
				}

			}
		}
	}

	while (!cbor_value_at_end(&val)) {
		DBG("Skipping\n");
		cbor_value_advance(&val);
	}

	if (cbor_value_leave_container(map_val, &val)) {
		DBG("Leaving slot failed\n");
		return -ENOMSG;
	}

	DBG("Checking keys complete\n");
	for (size_t i = 0; i < (sizeof(flags_def)/sizeof(flags_def[0])); ++i) {
		if (flags_def[i].required && !flags_def[i].found) {
			DBG("Missing key '%s'\n", flags_def[i].key);
			return -ENOMSG;
		}
	}
	if (!found_slot || !found_version || !found_hash) {
		DBG("Missing key 'slot', 'version' or 'hash'\n");
		return -ENOMSG;
	}
	return 0;

leave:

	return -ENOMSG;
}


/**
 * @brief Check and return the mgmt image state from an SMP message
 *
 * @param buf       The buffer holding the message
 * @param sz        Size of the buffer
 * @param mgmt_err  pointer where to save the mgmt return code
 * @param state     slots states
 * @return          0 on success and error code otherwise
 *
 * @retval 0 Successful execution.
 * @retval -EINVAL Argument validation failed
 * @retval -ENODATA @p buf too short to hold SMP header or not a complete SMP packet.
 * @retval -EPROTO Not the expected type of message, e.g. not a response, not a image state message
 * @retval -ENOBUFS @p state cannot hold the number of slots found in the response.
 * @retval -ENOMSG SMP payload decoding error or unexpected format, e.g. not a map, requested value has wrong format, ...
 */
int mgmt_img_decode_state_rsp(const uint8_t *buf, size_t sz, int64_t *mgmt_err, struct mgmt_image_state *state)
{
	CborParser parser;
	CborValue map_val;
	CborValue val;
	int rc;
	int64_t val64;
	int64_t rsp_rc = 0;
	bool images_found = false;

	rc = mgmt_header_len_check(buf, sz);
	if (rc) {
		return rc;
	}

	if (!mgmt_header_is_rsp(buf, sz)) {
		return -EPROTO;
	}

	rc = mgmt_header_check_rsp(buf, sz, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_STATE);
	if (rc) {
		return rc;
	}

	mgmt_header_advance(&buf, &sz);

	rc = mgmt_cbor_parser_init_enter_map(buf, sz, &parser, &map_val, &val);
	if (rc) {
		return rc;
	}

	memset(state, 0, sizeof(*state));

	while (!cbor_value_at_end(&val) && !rsp_rc) {
		size_t nlen = MGMT_CBOR_MAX_KEYLEN;
		char keyname[MGMT_CBOR_MAX_KEYLEN + 1];

		if (cbor_value_get_type(&val) != CborTextStringType) {
			break;
		}
		CborError ce;
		ce = cbor_value_copy_text_string(&val, keyname, &nlen, &val);
		if (ce) {
			if (ce == CborErrorOutOfMemory) {
				/* unexpected key, ignore */
				cbor_value_advance(&val);
				if (!cbor_value_at_end(&val)) {
					cbor_value_advance(&val);
				} else {
					return -ENOMSG;
				}
			} else {
				DBG("CborError keyname: %d\n", ce);
				return -ENOMSG;
			}
		}

		keyname[MGMT_CBOR_MAX_KEYLEN] = '\0';

		/* ignore unknown keys */
		if (!strcmp(keyname, "images")) {
			CborType vt;
			CborValue arr_elem;

			if (cbor_value_get_type(&val) != CborArrayType) {
				return -ENOMSG;
			}
			if (cbor_value_enter_container(&val, &arr_elem)) {
				return -ENOMSG;
			}
			images_found = true;

			/* array elements */
			while ((vt = cbor_value_get_type(&arr_elem)) != CborInvalidType) {
				if (vt == CborMapType) {
					if (state->num_slots < MGMT_IMAGE_STATE_SLOTS_MAX) {
						if (mgmt_img_parse_slot(&arr_elem, &state->slot[state->num_slots])) {
							return -ENOMSG;
						}
						// images_found = true;
						state->num_slots++;
					} else {
						return -ENOBUFS;
					}
				} else {
					DBG("Ignore array element: %x\n", cbor_value_get_type(&arr_elem));
					/* ignore for now */
					cbor_value_advance(&arr_elem);
				}
				DBG("Next array element: %x\n", cbor_value_get_type(&arr_elem));
			}

			/* end of array */
			cbor_value_leave_container(&val, &arr_elem);

		} else if (!strcmp(keyname, "rc")) {
			if (cbor_value_get_type(&val) != CborIntegerType) {
				return -ENOMSG;
			}
			cbor_value_get_int64(&val, &val64);
			rsp_rc = val64;
			*mgmt_err = rsp_rc;
		} else if (!strcmp(keyname, "splitStatus")) {
			if (cbor_value_get_type(&val) != CborIntegerType) {
				return -ENOMSG;
			}
			cbor_value_get_int64(&val, &val64);
			state->split_status = val64;
		}
	}

	if (!images_found && !rsp_rc) {
		return -EPROTO;
	} else if (images_found) {
		*mgmt_err = 0;
	}

	return 0;
}

/**
 * @brief Check and return the mgmt image list response from an SMP message
 *
 * @param buf       The buffer holding the message
 * @param sz        Size of the buffer
 * @param mgmt_err  pointer where to save the response

 * @return          0 on success and error code otherwise, @ref mgmt_img_decode_state_rsp
 */
int mgmt_img_decode_list_rsp(const uint8_t *buf, size_t sz, struct mgmt_image_state_rsp *rsp)
{
	return mgmt_img_decode_state_rsp(buf, sz, &rsp->mgmt_rc, &rsp->state);
}

/**
 * @brief Check and return the mgmt image test response from an SMP message
 *
 * @param buf       The buffer holding the message
 * @param sz        Size of the buffer
 * @param mgmt_err  pointer where to save the mgmt return code
 * @param state     slots states
 * @return          0 on success and error code otherwise, @ref mgmt_img_decode_state_rsp
 */
int mgmt_img_decode_test_rsp(const uint8_t *buf, size_t sz, struct mgmt_image_state_rsp *rsp)
{
	return mgmt_img_decode_state_rsp(buf, sz, &rsp->mgmt_rc, &rsp->state);
}

/**
 * @brief Check and return the mgmt image test response from an SMP message
 *
 * @param buf       The buffer holding the message
 * @param sz        Size of the buffer
 * @param rsp       where to save parsed resonse
 *
 * @return          0 on success and error code otherwise, @ref mgmt_img_decode_state_rsp
 */
int mgmt_img_decode_confirm_rsp(const uint8_t *buf, size_t sz, struct mgmt_image_state_rsp *rsp)
{
	return mgmt_img_decode_state_rsp(buf, sz, &rsp->mgmt_rc, &rsp->state);
}


ssize_t mgmt_create_image_upload_seg0_req(uint8_t *buf, size_t sz,
	size_t fw_sz, const uint8_t *fw_data, const uint8_t *fw_sha, size_t seglen)
{
	int rc;
	CborEncoder enc;
	CborEncoder map;
	struct mgmt_hdr *nh;
	int len;

	if (NULL == (nh = mgmt_header_init(buf, sz, MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_UPLOAD))) {
		return -ENOBUFS;
	}

	mgmt_cbor_encoder_init(&enc, buf, sz);

	rc = cbor_encoder_create_map(&enc, &map, CborIndefiniteLength);

	rc |= cbor_encode_text_stringz(&map, "sha");
	rc |= cbor_encode_byte_string(&map, fw_sha, 32);
	rc |= cbor_encode_text_stringz(&map, "off");
	rc |= cbor_encode_uint(&map, 0);
	rc |= cbor_encode_text_stringz(&map, "len");
	rc |= cbor_encode_uint(&map, fw_sz);
	rc |= cbor_encode_text_stringz(&map, "data");
	rc |= cbor_encode_byte_string(&map, fw_data, seglen);

	rc |= cbor_encoder_close_container(&enc, &map);
	if (rc) {
		return -ENOBUFS;
	}

	len = mgmt_cbor_encoder_get_buffer_size(&enc, buf);
	mgmt_header_set_len(nh, len);

	return len + MGMT_HEADER_LEN;
}

static int cbor_array_len_overhead(size_t len)
{
	if (len < 24) {
		return 0;
	}
	if (len < 256) {
		return 1;
	}
	if (len < 65535) {
		return 2;
	}
	/* do not expect bigger values */
	return 4;
}

size_t mgmt_image_calc_encode_overhead(size_t offset, size_t seglen)
{
	return cbor_array_len_overhead(offset) + cbor_array_len_overhead(seglen);
}


ssize_t mgmt_image_calc_data_size_seq0(int mtu, uint32_t file_sz, uint32_t chunk_max)
{
	uint8_t buf[MGMT_MAX_MTU];
	ssize_t cnt;
	ssize_t seglen;
	const uint8_t dummy_hash[MGMT_IMAGE_HASH_SIZE] = {0};

	size_t room;
	int enc_overhead;

	if (mtu > MGMT_MAX_MTU) {
		return -EINVAL;
	}
	/* Calculate space for data
	   Create initial request with minimal data (0 bytes) */
	cnt = mgmt_create_image_upload_seg0_req(buf, sizeof(buf), file_sz, NULL, dummy_hash, 0);
	if (cnt < 0) {
		return (ssize_t)cnt;
	}
	/* worst case bound, normally second parameter should be the max data chunk length we are caclulating,
	   This can never be bigger than MTU
	 */
	enc_overhead = mgmt_image_calc_encode_overhead(0, mtu);
	if (cnt + enc_overhead > (ssize_t) mtu) {
		return -EOVERFLOW;
	}
	/* account for header, base payload and data length field */
	room = mtu - cnt - enc_overhead;
	if (chunk_max && (room > chunk_max)) {
		seglen = chunk_max;
	} else {
		seglen = room;
	}
	return seglen;
}


ssize_t mgmt_image_calc_data_size_seqX(int mtu, uint32_t file_sz, uint32_t chunk_max)
{
	uint8_t buf[MGMT_MAX_MTU];
	ssize_t cnt;
	ssize_t seglen;

	size_t room;
	int enc_overhead;

	if (mtu > MGMT_MAX_MTU) {
		return -EINVAL;
	}
	/* Calculate space for data
	   Create initial request with minimal data (0 bytes) */
	cnt = mgmt_create_image_upload_segX_req(buf, sizeof(buf), 0, NULL, 0);
	if (cnt < 0) {
		return (ssize_t)cnt;
	}
	/* worst case bound, normally second parameter should be the max data chunk length we are caclulating,
	   This can never be bigger than MTU
	 */
	enc_overhead = mgmt_image_calc_encode_overhead(file_sz, mtu);
	if (cnt + enc_overhead > (ssize_t) mtu) {
		return -EOVERFLOW;
	}
	/* account for header, base payload and data length field */
	room = mtu - cnt - enc_overhead;
	if (chunk_max && (room > chunk_max)) {
		seglen = chunk_max;
	} else {
		seglen = room;
	}
	return seglen;
}


ssize_t mgmt_create_image_upload_segX_req(uint8_t *buf, size_t sz,
	size_t off, const uint8_t *data, size_t seglen)
{
	int rc;
	CborEncoder enc;
	CborEncoder map;
	struct mgmt_hdr *nh;
	int len;

	if (NULL == (nh = mgmt_header_init(buf, sz, MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_UPLOAD))) {
		return -ENOBUFS;
	}

	mgmt_cbor_encoder_init(&enc, buf, sz);

	rc = cbor_encoder_create_map(&enc, &map, CborIndefiniteLength);

	rc |= cbor_encode_text_stringz(&map, "off");
	rc |= cbor_encode_uint(&map, off);
	rc |= cbor_encode_text_stringz(&map, "data");
	rc |= cbor_encode_byte_string(&map, data, seglen);

	rc |= cbor_encoder_close_container(&enc, &map);
	if (rc) {
		return -ENOBUFS;
	}

	len = mgmt_cbor_encoder_get_buffer_size(&enc, buf);
	mgmt_header_set_len(nh, len);

	return len + MGMT_HEADER_LEN;
}


/**
 * @brief Check and return the mgmt echo return message from an SMP message
 *
 * @param buf       The buffer holding the message
 * @param sz        Size of the buffer
 * @param off       pointer where to save the new offset for the next upload chunk.
 * @param mgmt_err  pointer where to save the mgmt return code
 * @return          0 on success and error code otherwise
 *
 * @retval 0 Successful execution, @p off is valid.
 * @retval -EINVAL Argument validation failed
 * @retval -ENODATA @p buf too short to hold SMP header or not a complete SMP packet.
 * @retval -ENOMSG SMP payload decoding error or unexpected format, e.g. not a map, requested value has wrong format, ...
 */
int mgmt_img_upload_decode_rsp(const uint8_t *buf, size_t sz, size_t *off, struct mgmt_rc *rsp)
{
	CborParser parser;
	CborValue map_val;
	CborValue val;
	int rc;
	int64_t val64;
	int64_t rsp_off = -1;

	rc = mgmt_header_len_check(buf, sz);
	if (rc) {
		return rc;
	}

	rc = mgmt_header_check_rsp(buf, sz, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_UPLOAD);
	if (rc) {
		return rc;
	}

	mgmt_header_advance(&buf, &sz);

	rc = mgmt_cbor_parser_init_enter_map(buf, sz, &parser, &map_val, &val);
	if (rc) {
		return rc;
	}

	rsp->mgmt_rc = -1;

	while (!cbor_value_at_end(&val)) {
		if (cbor_value_get_type(&val) != CborTextStringType) {
			break;
		}
		size_t nlen = MGMT_CBOR_MAX_KEYLEN;
		char keyname[MGMT_CBOR_MAX_KEYLEN + 1];

		rc = cbor_value_copy_text_string(&val, keyname, &nlen, &val);
		keyname[MGMT_CBOR_MAX_KEYLEN] = '\0';

		if (rc) {
			return -ENOMSG;
		}
		if (cbor_value_get_type(&val) != CborIntegerType) {
			return -ENOMSG;
		}
		cbor_value_get_int64(&val, &val64);
		if (!strcmp(keyname, "rc")) {
			rsp->mgmt_rc = val64;
		} else if (!strcmp(keyname, "off")) {
			rsp_off = val64;
		}
		cbor_value_advance(&val);
	}
	*off = rsp_off;

	return 0;
}
