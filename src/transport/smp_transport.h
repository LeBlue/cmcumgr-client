/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SMP_TRANSPORT_H
#define SMP_TRANSPORT_H


#include <stdint.h>

struct smp_handle;
struct smp_transport;

typedef int (*transport_open_fn)(struct smp_transport* fh);
typedef int (*transport_init_fn)(struct smp_transport* fh, struct smp_handle *hd);
typedef int (*transport_connect_fn)(struct smp_transport* fh);
typedef int (*transport_read_fn)(struct smp_transport* fh, uint8_t *buf, size_t sz);
typedef int (*transport_write_fn)(struct smp_transport* fh, uint8_t *buf, size_t sz);
typedef void (*transport_close_fn)(struct smp_transport* fh);
typedef int (*transport_get_mtu_fn)(struct smp_transport* t);


struct smp_operations {
    transport_init_fn init;
    transport_connect_fn open;
    transport_read_fn read;
    transport_write_fn write;
    transport_close_fn close;
    transport_get_mtu_fn get_mtu;
};

struct smp_transport {
    struct smp_handle *hd;
    const struct smp_operations *ops;
    uint8_t retries;
    uint8_t timeout;
    uint8_t verbose;
};


#endif

