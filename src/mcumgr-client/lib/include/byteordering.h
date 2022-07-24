/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BYTE_ORDERING_H
#define BYTE_ORDERING_H

#include <stdint.h>

static inline void set_be16(uint8_t *buf, uint16_t val)
{
    buf[0] = val >> 8;
    buf[1] = val & 0xff;
}

static inline uint16_t get_be16(const uint8_t *buf)
{
    return (buf[0] << 8) | buf[1];
}

static inline uint32_t le32_to_host(uint32_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return (data[0] << 0) | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

static inline uint16_t le16_to_host(uint16_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return (data[0] << 0) | (data[1] << 8);
}

static inline uint32_t be32_to_host(uint32_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return (data[3] << 0 ) | (data[2] << 8) | (data[1] << 16) | (data[0] << 24);
}

static inline uint16_t be16_to_host(uint16_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return get_be16(data);
}

static inline uint32_t host_to_le32(uint32_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return (data[0] << 0) | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

static inline uint16_t host_to_le16(uint16_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return (data[0] << 0) | (data[1] << 8);
}

static inline uint32_t host_to_be32(uint32_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return (data[3] << 0 ) | (data[2] << 8) | (data[1] << 16) | (data[0] << 24);
}

static inline uint16_t host_to_be16(uint16_t val)
{
    uint8_t *data = (uint8_t*) &val;
    return (data[1] << 0) | (data[0] << 8);
}

#endif