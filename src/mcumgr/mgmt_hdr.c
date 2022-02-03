/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include "byteordering.h"
#include "mgmt_hdr.h"

struct mgmt_hdr {
    uint8_t  nh_op_res;         /* 5 bits reserved, 3 bits MGMT_OP_XXX */
    uint8_t  nh_flags;          /* XXX reserved for future flags */
    uint16_t nh_len;            /* length of the payload */
    uint16_t nh_group;          /* MGMT_GROUP_XXX */
    uint8_t  nh_seq;            /* sequence number */
    uint8_t  nh_id;             /* message ID within group */
};


#define MGMT_OP_SET(hdr, op)    ((hdr)->nh_op_res = (op) & 0x7)
#define MGMT_OP_GET(hdr)        ((hdr)->nh_op_res & 0x7)


struct mgmt_hdr *mgmt_header_init(uint8_t *buf, size_t sz, uint8_t op, uint16_t group, uint8_t id)
{
	struct mgmt_hdr *nh;

	if (sz < sizeof(*nh)) {
		return NULL;
	}

	nh = (struct mgmt_hdr *)buf;
	memset(nh, 0, sizeof(*nh));
	MGMT_OP_SET(nh, op);
	nh->nh_group = be16_to_host(group);
	nh->nh_id = id;

	return nh;
}

uint16_t mgmt_header_get_len(const struct mgmt_hdr *nh)
{
	return be16_to_host(nh->nh_len);
}

void mgmt_header_set_len(struct mgmt_hdr *nh, uint16_t len)
{
	nh->nh_len = host_to_be16(len);
}

int mgmt_header_is_rsp(const uint8_t *buf, size_t sz)
{
	int op;

	if (sz < sizeof(struct mgmt_hdr)) {
		return 0;
	}

	op = MGMT_OP_GET((struct mgmt_hdr *)buf);
	if (op != MGMT_OP_READ_RSP && op != MGMT_OP_WRITE_RSP) {
		return 0;
	}
	return 1;
}


int mgmt_header_is_rsp_complete(const uint8_t *buf, size_t sz)
{
	if (mgmt_header_len_check(buf, sz)) {
		return 0;
	}
	return 1;
}


int mgmt_header_is_rsp_to(const uint8_t *buf, size_t sz, uint16_t group, uint8_t id)
{
	struct mgmt_hdr *nh = (struct mgmt_hdr *)buf;

	if (mgmt_header_is_rsp(buf, sz) && (nh->nh_id == id) && (be16_to_host(nh->nh_group) == group)) {
		return 1;
	}
	return 0;
}

/**
 * @brief Check the SMP header and update @p buf and @p sz
 *
 * @param buf        pointer to message buffer, must not be NULL.
 * @param sz         pointer to size of message buffer (valid bytes) in @p buf , must not be NULL.
 *
 * @retval 0         SMP header is valid and buffer contains the whole SMP packet.
 * @retval -EINVAL   @p buf does not point to a buffer (is NULL)
 * @retval -ENODATA  @p buf does not contain enough data for a SMP header or the SMP packet is not complete.
 */
int mgmt_header_len_check(const uint8_t *buf, size_t sz)
{
	struct mgmt_hdr *nh;

	if (!buf) {
		return -EINVAL;
	}

	if (sz < sizeof(struct mgmt_hdr)) {
		return -ENODATA;
	}

	nh = (struct mgmt_hdr *)(buf);
	if ((sz - sizeof(*nh)) < mgmt_header_get_len(nh)) {
		return -ENODATA;
	}

	return 0;
}

void mgmt_header_advance(const uint8_t **buf, size_t *sz)
{
	*buf += sizeof(struct mgmt_hdr);
	*sz -= sizeof(struct mgmt_hdr);
}

/**
 * @brief Check the SMP header and update @p buf and @p sz
 *
 * @param buf        pointer to message buffer, must not be NULL. *buf will be checked against NULL.
 * @param sz         pointer to size of message buffer (valid bytes) in @p buf , must not be NULL.
 *
 * @retval 0         SMP header is valid and buffer contains the whole SMP packet. *buf and *sz are updated.
 * @retval -EINVAL   @p buf does not point to a buffer (is NULL)
 * @retval -ENODATA  @p buf does not contain enough data for a SMP header or the SMP packet is not complete.
 */
int mgmt_header_len_check_and_advance(const uint8_t **buf, size_t *sz)
{
	int rc = mgmt_header_len_check(*buf, *sz);
	if (rc) {
		return rc;
	}

	mgmt_header_advance(buf, sz);

	return 0;
}

/**
 * @brief update seqential number in mgmt header
 *
 * Every new message should use a incremented @p seq .
 * The same @p seq number will be in the response
 *
 * @param buf buffer used to construct mgmt message. Must be valid.
 * @param seq new sequential number to set
 */
void mgmt_header_update_seq(uint8_t *buf, uint8_t seq)
{
	struct mgmt_hdr *nh;

	nh = (struct mgmt_hdr *)buf;
	nh->nh_seq = seq;
}

/**
 * @brief get seqential number in mgmt header
 *
 * Every new message should use a incremented @p seq .
 * The same @p seq number will be in the response
 *
 * @param buf buffer with a mgmt message. Must be valid.
 * @param seq new sequential number to set
 */
uint8_t mgmt_header_get_seq(uint8_t *buf)
{
	struct mgmt_hdr *nh;

	nh = (struct mgmt_hdr *)buf;
	return nh->nh_seq;
}

