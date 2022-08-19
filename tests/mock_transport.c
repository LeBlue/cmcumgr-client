/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */
#include <assert.h>

#include "mock_transport.h"

#include "utils_test.h"

static const struct smp_operations mock_transport_ops = {
    .open = mock_transport_connect,
    .read = mock_transport_read,
    .write = mock_transport_write,
    .close = mock_transport_close,
};

int mock_transport_init(struct smp_transport *transport, struct smp_mock_handle *hd)
{
    if (!transport || !hd) {
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    memset(hd, 0, sizeof(*hd));

    transport->ops = &mock_transport_ops;
    transport->hd = (struct smp_handle*) hd;

    return 0;
}

void mock_handle_add_response(struct smp_mock_handle *hd, const uint8_t *buf, size_t sz)
{
    ASSERT_TEST_MSG(hd->n_rx_buf < (MAX_CHUNKS - 1), "More packets responses added (%d) than supported by mock", MAX_CHUNKS);

    int idx = hd->n_rx_buf;
    if (sz) {
        ASSERT_TEST_MSG(buf, "Test buf is NULL");
        hd->rxbufs[idx].data = buf;
    } else {
        hd->rxbufs[idx].sz = 0;
    }

    hd->rxbufs[idx].sz = sz;
    hd->n_rx_buf++;
}

void mock_transport_add_response(struct smp_transport *t, const uint8_t *buf, size_t sz)
{
    struct smp_mock_handle *hd = (struct smp_mock_handle*) t->hd;

    mock_handle_add_response(hd, buf, sz);
}

void mock_transport_get_written(struct smp_mock_handle *hd, const uint8_t *buf, size_t sz)
{
    (void)hd;
    (void)buf;
    (void)sz;
}

int mock_transport_write(struct smp_transport *t, uint8_t *buf, size_t sz)
{
    struct smp_mock_handle *hd;
    int idx;

    if (!t || !buf || !sz) {
        return -EINVAL;
    }

    hd = (struct smp_mock_handle*) t->hd;
    ASSERT_TEST_MSG(hd->next_tx < (MAX_CHUNKS - 1), "More packets written (%d) than supported by mock", hd->next_tx);

    idx = hd->next_tx;


    hd->txbufs[idx].data = malloc(sz);
    ASSERT_TEST_MSG(hd->txbufs[idx].data != NULL, "Test mem alloc failed");

    memcpy(hd->txbufs[idx].data, buf, hd->txbufs[idx].sz);

    hd->next_tx++;
    return hd->txbufs[idx].sz;
}

int mock_transport_read(struct smp_transport *t, uint8_t *buf, size_t sz)
{
    struct smp_mock_handle *hd = (struct smp_mock_handle*) t->hd;
    if (hd->n_rx_buf <= hd->next_rx) {
        return -ETIMEDOUT;
    }
    int idx = hd->next_rx;

    if (sz < hd->rxbufs[idx].sz) {
        // memcpy(buf, hd->rxbufs[idx].data, sz);
        hd->next_rx++;
        return -ENOBUFS;
    } else {
        memcpy(buf, hd->rxbufs[idx].data, hd->rxbufs[idx].sz);
    }

    hd->next_rx++;
    return hd->rxbufs[idx].sz;
}

int mock_transport_connect(struct smp_transport *t)
{
    if (!t) {
        return -EINVAL;
    }
    return 0;
}

void mock_transport_close(struct smp_transport* fh)
{
    (void)fh;
}


void cleanup_smp_handle(struct smp_mock_handle *hd)
{
    (void)hd;

    for (int idx = 0; idx < hd->n_tx_buf; ++idx)
    {
        free(hd->txbufs[idx].data);
    }
}


void cleanup_smp_mock(struct smp_transport *t)
{
    struct smp_mock_handle *hd = (struct smp_mock_handle*) t->hd;
    cleanup_smp_handle(hd);
}

static struct smp_transport tmock = {0};
static struct smp_mock_handle mhd = {0};

struct smp_transport *setup_smp_mock(void)
{
    memset(&tmock, 0, sizeof(tmock));
    memset(&mhd, 0, sizeof(mhd));

    mock_transport_init(&tmock, &mhd);

    return &tmock;
}
