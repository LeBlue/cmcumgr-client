/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#ifndef __UTIL_BASE64_H
#define __UTIL_BASE64_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief base64 encode @p data
 *
 * @param data        Data to encode
 * @param size        Size of data to encode
 * @param buf         Buffer where to write the encoded data
 * @param should_pad  If the encoded data should be padded
 *
 * @return            The encoded data length
 */
int base64_encode(const void *data, int size, char *buf, uint8_t should_pad);

/**
 * @brief
 *
 * @param str
 * @param data
 * @return int
 */
int base64_decode(const char *str, void *data);

/**
 * @brief pad base64 encoded data
 *
 * @param buf  Encoded data to pad
 * @param len  Lenght of encoded data
 *
 * @return int
 */
int base64_pad(char *buf, int len);

/**
 * @brief       Calulate unencoded data length of base64 encoded data string
 *
 * @param str   base64 encoded data
 * @return int  Size of decoded data
 */
int base64_decode_len(const char *str);

/**
 * @brief       Calulate unencoded data length of base64 encoded data string
 *
 * @param str   base64 encoded data
 * @param str   string len
 * @return int  Size of decoded data
 */
int base64_decode_size(const char *str, int len);

#define BASE64_ENCODE_SIZE(__size) (((((__size) - 1) / 3) * 4) + 4)

/**
 * @brief       Calculate base64 encoded data length, based of plain data length
 *
 * @param size  Size of unencoded data
 * @return int  Size of base64 encoded data
 */
static inline int base64_encoded_len(int size) {
    return BASE64_ENCODE_SIZE(size);
}

#ifdef __cplusplus
}
#endif

#endif /* __UTIL_BASE64_H__ */
