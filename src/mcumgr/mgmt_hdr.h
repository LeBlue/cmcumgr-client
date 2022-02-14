/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MGMT_HEADER_H
#define MGMT_HEADER_H

struct mgmt_hdr;

#define MGMT_HEADER_LEN         (8)

#define MGMT_OP_READ            (0)
#define MGMT_OP_READ_RSP        (1)
#define MGMT_OP_WRITE           (2)
#define MGMT_OP_WRITE_RSP       (3)

/* First 64 groups are reserved for system level newtmgr commands.
 * Per-user commands are then defined after group 64.
 */
#define MGMT_GROUP_ID_DEFAULT   (0)
#define MGMT_GROUP_ID_OS        (0)
#define MGMT_GROUP_ID_IMAGE     (1)
#define MGMT_GROUP_ID_STATS     (2)
#define MGMT_GROUP_ID_CONFIG    (3)
#define MGMT_GROUP_ID_LOGS      (4)
#define MGMT_GROUP_ID_CRASH     (5)
#define MGMT_GROUP_ID_SPLIT     (6)
#define MGMT_GROUP_ID_RUN       (7)
#define MGMT_GROUP_ID_FS        (8)
#define MGMT_GROUP_ID_PERUSER   (64)

#define OS_MGMT_ID_ECHO            0
#define OS_MGMT_ID_CONS_ECHO_CTRL  1
#define OS_MGMT_ID_TASKSTATS       2
#define OS_MGMT_ID_MPSTATS         3
#define OS_MGMT_ID_DATETIME_STR    4
#define OS_MGMT_ID_RESET           5

#define IMG_MGMT_ID_STATE        0
#define IMG_MGMT_ID_UPLOAD       1
#define IMG_MGMT_ID_FILE         2
#define IMG_MGMT_ID_CORELIST     3
#define IMG_MGMT_ID_CORELOAD     4
#define IMG_MGMT_ID_ERASE        5
#define IMG_MGMT_ID_ERASE_STATE  6



#ifdef __cplusplus
extern "C" {
#endif


struct mgmt_hdr *mgmt_header_init(uint8_t *buf, size_t sz, uint8_t op, uint16_t group, uint8_t id);
uint16_t mgmt_header_get_len(const struct mgmt_hdr *nh);
void mgmt_header_set_len(struct mgmt_hdr *nh, uint16_t len);
int mgmt_header_is_rsp(const uint8_t *buf, size_t sz);
int mgmt_header_is_rsp_to(const uint8_t *buf, size_t sz, uint16_t group, uint8_t id);
int mgmt_header_is_rsp_complete(const uint8_t *buf, size_t sz);


/**
 * @brief Check smp header for correct command/group IDs
 *
 * @param buf        pointer to message buffer, must contain the whole header.
 * @param sz         size of message buffer (valid bytes) in @p buf
 * @param group      expected group ID
 * @param id         expected command id
 * @return           0 if check passed, -EPROTO otherwise (unexpected IDs or no repsonse)
 */
int mgmt_header_check_rsp(const uint8_t *buf, size_t sz, uint16_t group, uint8_t id);

/**
 * @brief Check the SMP header and verify the buffer contains a whole message
 *
 * @param buf        pointer to message buffer
 * @param sz         size of message buffer (valid bytes) in @p buf
 *
 * @retval 0         SMP header is valid and buffer contains the whole SMP packet.
 * @retval -EINVAL   @p buf does not point to a buffer (is NULL)
 * @retval -ENODATA  @p buf does not contain enough data for a SMP header or the SMP packet is not complete.
 */
int mgmt_header_len_check(const uint8_t *buf, size_t sz);

/**
 * @brief Advance @p buf pointer to the first payload byte, update @p sz
 *
 * @param buf The buffer containing the smp packet, must contain whole header
 * @param sz  Number of valid bytes in @p buf
 */
void mgmt_header_advance(const uint8_t **buf, size_t *sz);

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
int mgmt_header_len_check_and_advance(const uint8_t **buf, size_t *sz);

/**
 * @brief update seqential number in mgmt header
 *
 * Every new message should use a incremented @p seq .
 * The same @p seq number will be in the response
 *
 * @param buf buffer used to construct mgmt message. Must be valid.
 * @param seq new sequential number to set
 */
void mgmt_header_update_seq(uint8_t *buf, uint8_t seq);

/**
 * @brief get seqential number in mgmt header
 *
 * Every new message should use a incremented @p seq .
 * The same @p seq number will be in the response
 *
 * @param buf buffer with a mgmt message. Must be valid.
 * @param seq new sequential number to set
 */
uint8_t mgmt_header_get_seq(uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif