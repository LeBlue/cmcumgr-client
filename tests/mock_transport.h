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

#include "mcumgr-client/smp_transport.h"

#define MOCK_BUF_SZ 2048
#define MAX_CHUNKS 20

struct rxbuf {
    const uint8_t *data;
    size_t sz;
};

struct txbuf {
    uint8_t *data;
    size_t sz;
};


struct smp_mock_handle {
    struct rxbuf rxbufs[MAX_CHUNKS];
    int n_rx_buf;
    int next_rx;

    struct txbuf txbufs[MAX_CHUNKS];
    int n_tx_buf;
    int next_tx;

};


int mock_transport_init(struct smp_transport *transport, struct smp_mock_handle *hd);
void mock_handle_add_response(struct smp_mock_handle *hd, const uint8_t *buf, size_t sz);
void mock_transport_add_response(struct smp_transport *t, const uint8_t *buf, size_t sz);
void mock_transport_get_written(struct smp_mock_handle *hd, const uint8_t *buf, size_t sz);
int mock_transport_write(struct smp_transport *t, uint8_t *buf, size_t sz);
int mock_transport_read(struct smp_transport *t, uint8_t *buf, size_t sz);
int mock_transport_connect(struct smp_transport *t);

void mock_transport_close(struct smp_transport* fh);

void cleanup_smp_handle(struct smp_mock_handle *hd);

void cleanup_smp_mock(struct smp_transport *t);
struct smp_transport *setup_smp_mock(void);
