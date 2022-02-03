/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MGMT_COMMON_H
#define MGMT_COMMON_H

#include <stdint.h>
#include <stddef.h>

#include "cbor.h"


#ifdef __cplusplus
extern "C" {
#endif



void mgmt_cbor_encoder_init(CborEncoder *enc, uint8_t *buf, size_t sz);
size_t mgmt_cbor_encoder_get_buffer_size(CborEncoder *enc, uint8_t *buf);

size_t mgmt_create_generic_no_data_req(uint8_t *buf, size_t sz, uint8_t op, uint16_t group, uint8_t id);


int mgmt_cbor_parser_init(const uint8_t *buf, size_t sz, CborParser *parser, CborValue *map_val);
int mgmt_cbor_parser_init_enter_map(const uint8_t *buf, size_t sz, CborParser *parser, CborValue *map_val, CborValue *val);


int mgmt_decode_rsp_single_int64(const uint8_t *buf, size_t sz, const char* keyname, int64_t *retval);
int mgmt_decode_rsp_single_stringz(const uint8_t *buf, size_t sz, const char* keyname, char *str, size_t strsz);



#ifdef __cplusplus
}
#endif


#endif