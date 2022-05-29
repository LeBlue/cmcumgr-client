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

#include "ptest/ptest.h"
#include "utils_test.h"

#include "mcumgr-client/smp_serial.h"
#include "mcumgr-client/smp_transport.h"

/* mock serial port */
#include "serial_port.h"


#define MOCK_BUF_SZ 2048
#define MAX_CHUNKS 20
struct serial_mock_state {
    uint8_t read_poll_wait;

    /* data that is read from port */
    uint8_t rx_buf[MOCK_BUF_SZ];
    size_t rx_off;
    size_t rx_size;

    size_t chunk_len[MAX_CHUNKS];
    int n_chunks;
    int chunk;

    /* data that is written to port */
    uint8_t tx_buf[MOCK_BUF_SZ];
    size_t tx_off;
};

static struct serial_mock_state serial_state = {0};
static int current_time = 0;

int time_get(void)
{
    /* 200 ms per call */
    current_time += 100;

    return current_time/1000;
}

void mock_serial_port_init(void)
{
    current_time = 0;
    memset(&serial_state, 0, sizeof(serial_state));
}

/* avoid discards const warnings, need additional space also (crc): TODO: fix impl */
uint8_t *tx_copy_msg(const uint8_t *buf, size_t sz)
{
    uint8_t *new_buf = malloc(sz + 2);
    assert(new_buf);
    memcpy(new_buf, buf, sz);
    return new_buf;
}


/* add data in chunks to simulate partial reads */
void mock_add_rx_chunk(const uint8_t *data, size_t sz)
{
    serial_state.rx_size += sz;
    if (serial_state.rx_size > MOCK_BUF_SZ) {
        /* abort test */
        fprintf(stderr, "Test ERROR: Static buffer too low for test: MOCK_BUF_SZ\n");
        assert(serial_state.rx_size <= MOCK_BUF_SZ);
    }
    if (serial_state.n_chunks >= MAX_CHUNKS) {
        /* abort test */
        fprintf(stderr, "Test ERROR: Static buffer too low for test: MAX_CHUNKS\n");
        assert(serial_state.n_chunks < MAX_CHUNKS);
    }
    serial_state.chunk_len[serial_state.n_chunks++] = sz;

    if (sz && data) {
        memcpy(serial_state.rx_buf + serial_state.rx_size - sz, data, sz);
    }
}

#define RX_CHUNK(_data) \
    mock_add_rx_chunk(_data, sizeof(_data))

/* add to simulate data pause */
void mock_add_rx_empty_chunk(void) {
    mock_add_rx_chunk(NULL, 0);
}

/* for loopback test */
void mock_move_tx_to_rx(void) {
    mock_add_rx_chunk(serial_state.tx_buf, serial_state.tx_off);
}


/* mocked functions */
HANDLE port_open(const char *name) {
    (void) name;
    return 1;
}

int port_setup(HANDLE fd, unsigned long speed) {
    (void)fd;
    (void)speed;

    return 0;
}

int port_write_data(HANDLE fd, const void *buf, size_t len)
{
    (void) fd;
    memcpy(serial_state.tx_buf + serial_state.tx_off, buf, len);
    serial_state.tx_off += len;
    return len;
}

int port_read_poll(HANDLE fd, char *buf, size_t maxlen, int end_time, int verbose)
{
   (void)fd;
   (void)verbose;

    while (1) {
        int now = time_get();
        if (now > end_time) {
            return -ETIMEDOUT;
        }

        /* no more data setup to read */
        if (serial_state.chunk > serial_state.n_chunks) {
            /* since original API waits until something rxed, simulate a timeout */
            return -ETIMEDOUT;
        }

        size_t chunk = serial_state.chunk_len[serial_state.chunk];

        if (chunk > 0) {
            if (chunk > maxlen) {
                chunk = maxlen;
                serial_state.chunk_len[serial_state.chunk] -= maxlen;
            } else {
                serial_state.chunk++;
            }
            memcpy(buf, serial_state.rx_buf + serial_state.rx_off, chunk);
            serial_state.rx_off += chunk;
            return chunk;
        } else {
            serial_state.chunk++;
        }
    }
    return -ETIMEDOUT;
}

void port_close(HANDLE fd)
{
    (void)fd;
}

static struct serial_opts sopts = {
    .port_name = "",
    .speed = 9600,
};

static struct smp_transport transport;
static struct smp_serial_handle serial_handle;

void init_serial_transport(void)
{
    if (serial_transport_init(&transport, &serial_handle, &sopts)) {
        fprintf(stderr, "Failed to init transport\n");
        exit(EXIT_FAILURE);
    }
    if (transport.ops->open(&transport)) {
        fprintf(stderr, "Failed to open transport\n");
        exit(EXIT_FAILURE);
    }
}


static void test_smp_serial_write_hello(void)
{
    const uint8_t tx_data_const[5] = "Hello";
    size_t tx_len = sizeof(tx_data_const);
    uint8_t *tx_data = tx_copy_msg(tx_data_const, tx_len);
    const uint8_t tx_enc_data[15] = "\x06\x09" "AAdIZWxsb8vW" "\n";

    mock_serial_port_init();

    int rc = transport.ops->write(&transport, tx_data, tx_len);

    PT_ASSERT(rc == 0);
    PT_ASSERT(serial_state.tx_off == sizeof(tx_enc_data));

    PT_ASSERT_MEM_EQ(serial_state.tx_buf, tx_enc_data, sizeof(tx_enc_data));
}


static void test_smp_serial_write_mgmt_rc(void)
{
    const uint8_t tx_data_const[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";
    size_t tx_len = sizeof(tx_data_const);
    uint8_t *tx_data = tx_copy_msg(tx_data_const, tx_len);

    const uint8_t tx_enc_data[27] = "\x06\x09"
                                    "ABACAAAGAAAAAL"
                                    "9icmMA/xcQ" "\n";

    mock_serial_port_init();

    int rc = transport.ops->write(&transport, tx_data, tx_len);

    PT_ASSERT(rc == 0);
    PT_ASSERT(serial_state.tx_off == sizeof(tx_enc_data));
    PT_ASSERT_MEM_EQ(serial_state.tx_buf, tx_enc_data, sizeof(tx_enc_data));
}


static void test_smp_serial_read(void)
{
    const uint8_t rx_enc_data[27] = "\x06\x09"
                                    "ABACAAAGAAAAAL"
                                    "9icmMA/xcQ" "\n";

    /* should be decoded to this */
    const uint8_t exp_rx_data[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";

    mock_serial_port_init();

    mock_add_rx_chunk(rx_enc_data, sizeof(rx_enc_data));

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}


static void test_smp_serial_read_wrong_pktlen(void)
{
    const uint8_t rx_enc_data[27] = "\x06\x09"
                                    "AA4CAAAGAAAAAL"
                                    "9icmMA/xcQ" "\n";

    /* should be decoded to this */
    const uint8_t exp_rx_data[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";

    mock_serial_port_init();

    mock_add_rx_chunk(rx_enc_data, sizeof(rx_enc_data));

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}


static void test_smp_serial_read_timeout(void)
{
    const uint8_t rx_enc_data[23] = "\x06\x09"
                                    "ABACAAAGAAAAAL"
                                    "9icmMA/"; /* cut: "xcQ" "\n" */

    mock_serial_port_init();

    mock_add_rx_chunk(rx_enc_data, sizeof(rx_enc_data));

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == -ETIMEDOUT);
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}


static void test_smp_serial_read_garbage_before(void)
{
    /* make transport receive this */
    const uint8_t rx_enc_data[28] = "\n" "\x06\x09"
                                    "ABACAAAGAAAAAL"
                                    "9icmMA/xcQ" "\n";

    /* should be decoded to this */
    const uint8_t exp_rx_data[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";
    const uint8_t garbage1[6] = "ab\ncag";
    const uint8_t garbage2[6] = "\x06\x00" "cag\n";

    mock_serial_port_init();

    /* add rx data to mock */
    mock_add_rx_chunk(garbage1, sizeof(garbage1));
    mock_add_rx_chunk(garbage2, sizeof(garbage2));
    mock_add_rx_chunk(rx_enc_data, sizeof(rx_enc_data));

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_chunked(void)
{
    /* make transport receive this */
    const uint8_t rx_enc_data[28] = "\n" "\x06\x09"
                                    "ABACAAAGAAAAAL"
                                    "9icmMA/xcQ" "\n";

    /* should be decoded to this */
    const uint8_t exp_rx_data[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";

    size_t chunk1 = 9;
    size_t chunk2 = 10;

    mock_serial_port_init();

    mock_add_rx_chunk(rx_enc_data, chunk1);
    mock_add_rx_chunk(rx_enc_data + chunk1, chunk2);
    mock_add_rx_chunk(rx_enc_data + chunk1 + chunk2, sizeof(rx_enc_data) - (chunk1 + chunk2));

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_chunked_unaligned(void)
{
    /* make transport receive this, first byte in chunk before */
    const uint8_t rx_enc_data[26] = "\x09"
                                    "ABACAAAGAAAAAL"
                                    "9icmMA/xcQ" "\n";

    /* should be decoded to this */
    const uint8_t exp_rx_data[14] = "\x02\x00\x00\x06\x00\x00\x00\x00" "\xbf" "brc" "\x00\xff";
    const uint8_t garbage1[7] = "ab\ncag" "\x06"; /* include first valid byte */
    size_t chunk1 = 9;
    size_t chunk2 = 10;

    mock_serial_port_init();
    mock_add_rx_chunk(garbage1, sizeof(garbage1));
    mock_add_rx_empty_chunk();
    mock_add_rx_chunk(rx_enc_data, chunk1);
    mock_add_rx_chunk(rx_enc_data + chunk1, chunk2);
    mock_add_rx_empty_chunk();
    mock_add_rx_chunk(rx_enc_data + chunk1 + chunk2, sizeof(rx_enc_data) - (chunk1 + chunk2));

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}


static void test_smp_serial_read_split_packet(void)
{
    /* split packet means multiple smp_serial packets (splitting on the transport layer, not smp layer)

        It contains here a single mcumgr frame, NOT a mcumgr fragmented packet

    */
    /* make transport receive this */
    const uint8_t rx_enc_data1[127] = "\x06\x09"
                                      "AHMDAABpAAAAAKFhcnhkMTIzNDU2Nzg5"
                                      "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz"
                                      "NDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3"
                                      "ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4"
                                      "\n";

    const uint8_t rx_enc_data2[35] = "\x04\x14"
                                     "OTAxMjM0"
                                     "NTY3ODkwMTIzNDU2Nzg5MKkq"
                                     "\n";
    /* should be decoded to this:
        echo response, with string '1234567890' * 10
    */
    const uint8_t exp_rx_data[113] = "\x03\x00\x00\x69\x00\x00\x00\x00"
                                    "\xa1" "arxd"
                                    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";


    mock_serial_port_init();

    mock_add_rx_chunk(rx_enc_data1, sizeof(rx_enc_data1));
    mock_add_rx_chunk(rx_enc_data2, sizeof(rx_enc_data2));

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));

    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_chunked_packet(void)
{
    /* chunked packet means the response is split on serial layer */
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 250 */
	/* Full SMP packet */
	const uint8_t exp_rx_data[63] =
		"\x03\x00\x00\x37\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x32\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[95] =
		"\x06\x09"
		"AEEDAAA3AAAAAKFh"
		"cngyMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTDprA==" "\x0a";

    mock_serial_port_init();

    RX_CHUNK(chunk_0_0);

    uint8_t rbuf[128];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));

    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_chunked_packet_2(void)
{
    /* chunked packet means the response is split on serial layer */
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 250 */
	/* Full SMP packet */
	const uint8_t exp_rx_data[133] =
		"\x03\x00\x00\x7d\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x78\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"6789012345678901"
		"2345678901234567"
		"8901234567890";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AIcDAAB9AAAAAKFh"
		"cnh4MTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4" "\x0a";
	/* SMP serial fragment 0 chunk: 1 */
	const uint8_t chunk_0_1[63] =
		"\x04\x14"
		"OTAxMjM0NTY3ODkw"
		"MTIzNDU2Nzg5MDEy"
		"MzQ1Njc4OTAxMjM0"
		"NTY3ODkwg64=" "\x0a";


    mock_serial_port_init();

    RX_CHUNK(chunk_0_0);
    RX_CHUNK(chunk_0_1);

    uint8_t rbuf[140];
    memset(rbuf, 0xaa, sizeof(rbuf));
    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));

    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}


/* transport read has not enough buffer to hold whole smp packet
    test with multiple different sizes. Share this data
 */
/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
    max fragment size: 250 */
/* Full SMP packet */
static const uint8_t smp2big_exp_rx_data[133] =
    "\x03\x00\x00\x7d\x00\x00\x00\x00"
    "\xa1\x61\x72\x78\x78\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
    "2345678901234567"
    "8901234567890123"
    "4567890123456789"
    "0123456789012345"
    "6789012345678901"
    "2345678901234567"
    "8901234567890";
/* SMP serial fragment 0 chunk: 0 */
static const uint8_t smp2big_chunk_0_0[127] =
    "\x06\x09"
    "AIcDAAB9AAAAAKFh"
    "cnh4MTIzNDU2Nzg5"
    "MDEyMzQ1Njc4OTAx"
    "MjM0NTY3ODkwMTIz"
    "NDU2Nzg5MDEyMzQ1"
    "Njc4OTAxMjM0NTY3"
    "ODkwMTIzNDU2Nzg5"
    "MDEyMzQ1Njc4" "\x0a";
/* SMP serial fragment 0 chunk: 1 */
static const uint8_t smp2big_chunk_0_1[63] =
    "\x04\x14"
    "OTAxMjM0NTY3ODkw"
    "MTIzNDU2Nzg5MDEy"
    "MzQ1Njc4OTAxMjM0"
    "NTY3ODkwg64=" "\x0a";


static void test_smp_serial_read_pkt_just_enough(void)
{
    /* exactly enough buf space. */
    size_t buflen = sizeof(smp2big_exp_rx_data) + 2; /* tested buffer size, 2 extra for crc needed */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    int rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc == sizeof(smp2big_exp_rx_data));
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */

    PT_ASSERT_MEM_EQ(smp2big_exp_rx_data, rbuf, sizeof(smp2big_exp_rx_data));
}


static void test_smp_serial_read_pkt_too_big_1(void)
{
    /* really no buf space. (1 byte) */
    size_t buflen = 1; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    int rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
    (void)smp2big_exp_rx_data;
}


static void test_smp_serial_read_pkt_too_big_oneless(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = sizeof(smp2big_exp_rx_data) - 1 + 2; /* tested buffer size, +2 for crc needed */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    int rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
    (void)smp2big_exp_rx_data;
}


static void test_smp_serial_read_pkt_too_big_data_1_chunk_0(void)
{
    /* not enough buf space to decode data 1. byte */
    size_t buflen = 0; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    int rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
    (void)smp2big_exp_rx_data;
}


static void test_smp_serial_read_pkt_too_big_data_chunk_0(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = 93; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    int rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
    (void)smp2big_exp_rx_data;
}


static void test_smp_serial_read_pkt_too_big_data_1_chunk_1(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = sizeof(smp2big_exp_rx_data) - 1; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    int rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
    (void)smp2big_exp_rx_data;
}


static void test_smp_serial_read_pkt_too_big_data_chunk_1(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = sizeof(smp2big_exp_rx_data) - 1; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    int rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
    (void)smp2big_exp_rx_data;
}


static void test_smp_serial_read_pkt_too_big_2(void)
{
    /* transport read has not enough buffer to hold whole smp packet */
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 250 */
	/* Full SMP packet */
	const uint8_t exp_rx_data[133] =
		"\x03\x00\x00\x7d\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x78\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"6789012345678901"
		"2345678901234567"
		"8901234567890";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AIcDAAB9AAAAAKFh"
		"cnh4MTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4" "\x0a";
	/* SMP serial fragment 0 chunk: 1 */
	const uint8_t chunk_0_1[63] =
		"\x04\x14"
		"OTAxMjM0NTY3ODkw"
		"MTIzNDU2Nzg5MDEy"
		"MzQ1Njc4OTAxMjM0"
		"NTY3ODkwg64=" "\x0a";

    mock_serial_port_init();

    RX_CHUNK(chunk_0_0);
    RX_CHUNK(chunk_0_1);

    uint8_t rbuf[sizeof(exp_rx_data)];
    memset(rbuf, 0xaa, sizeof(exp_rx_data));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[sizeof(exp_rx_data) - 1] == 0xaa);
    (void)exp_rx_data;
}

static void test_smp_serial_read_pkt_too_big_fragmented(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 100 */
	/* Full SMP packet */
	const uint8_t exp_rx_data[133] =
		"\x03\x00\x00\x7d\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x78\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"6789012345678901"
		"2345678901234567"
		"8901234567890";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AGYDAAB9AAAAAKFh"
		"cnh4MTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4" "\x0a";
	/* SMP serial fragment 0 chunk: 1 */
	const uint8_t chunk_0_1[19] =
		"\x04\x14"
		"OTAxMjM0NTY3mdg="
		"" "\x0a";
	/* SMP serial fragment 1 chunk: 0 */
	const uint8_t chunk_1_0[55] =
		"\x06\x09"
		"ACM4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTDx"
		"8g==" "\x0a";

    mock_serial_port_init();

    RX_CHUNK(chunk_0_0);
    RX_CHUNK(chunk_0_1);
    RX_CHUNK(chunk_1_0);

    uint8_t rbuf[sizeof(exp_rx_data) + 2 + 1 - 1];
    memset(rbuf, 0xaa, sizeof(rbuf));

    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
    (void)exp_rx_data;
}

static void test_smp_serial_read_fragmented_pkt_chunked(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 100 */
	/* Full SMP packet */
	const uint8_t exp_rx_data[133] =
		"\x03\x00\x00\x7d\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x78\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"6789012345678901"
		"2345678901234567"
		"8901234567890";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AGYDAAB9AAAAAKFh"
		"cnh4MTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4" "\x0a";
	/* SMP serial fragment 0 chunk: 1 */
	const uint8_t chunk_0_1[19] =
		"\x04\x14"
		"OTAxMjM0NTY3mdg="
		"" "\x0a";
	/* SMP serial fragment 1 chunk: 0 */
	const uint8_t chunk_1_0[55] =
		"\x06\x09"
		"ACM4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTDx"
		"8g==" "\x0a";

    mock_serial_port_init();

    RX_CHUNK(chunk_0_0);
    RX_CHUNK(chunk_0_1);
    RX_CHUNK(chunk_1_0);

    uint8_t rbuf[sizeof(exp_rx_data) + 2 + 1];
    memset(rbuf, 0xaa, sizeof(rbuf));
    transport.verbose = 2;
    int rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));

    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));

    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}


static void suite_smp_serial(void)
{
    const char *sn =  "Suite SMP serial transport";

    pt_add_test(test_smp_serial_write_hello, "Serial port write: Hello", sn);
    pt_add_test(test_smp_serial_write_mgmt_rc, "Serial port write: MGMT RC", sn);

    pt_add_test(test_smp_serial_read, "Serial port read: MGMT RC", sn);
    pt_add_test(test_smp_serial_read_wrong_pktlen, "Serial port read: pktlen -2: MGMT RC", sn);
    pt_add_test(test_smp_serial_read_timeout, "Serial port read: timeout", sn);
    pt_add_test(test_smp_serial_read_garbage_before, "Serial port read: garbage before: MGMT RC", sn);
    pt_add_test(test_smp_serial_read_chunked, "Serial port read: chunked: MGMT RC", sn);
    pt_add_test(test_smp_serial_read_chunked_unaligned, "Serial port read: chunked unaligned: MGMT RC", sn);
    pt_add_test(test_smp_serial_read_split_packet, "Serial port read: split packet: MGMT RC", sn);
    pt_add_test(test_smp_serial_read_chunked_packet, "Serial port read: chunked smp packet: echo rsp", sn);
    pt_add_test(test_smp_serial_read_chunked_packet_2, "Serial port read: chunked smp packet 2: echo rsp", sn);


    pt_add_test(test_smp_serial_read_pkt_just_enough,  "Serial port read: unfragmented packet 2: pkt just fits", sn);

    pt_add_test(test_smp_serial_read_pkt_too_big_1,  "Serial port read: unfragmented packet: pkt too big 1 byte", sn);
    pt_add_test(test_smp_serial_read_pkt_too_big_oneless,  "Serial port read: unfragmented packet: pkt too big -1 byte", sn);
    pt_add_test(test_smp_serial_read_pkt_too_big_data_1_chunk_0,  "Serial port read: unfragmented packet: pkt too big: data 1 chunk 0", sn);
    pt_add_test(test_smp_serial_read_pkt_too_big_data_chunk_0,  "Serial port read: unfragmented packet: pkt too big: data chunk 0", sn);
    pt_add_test(test_smp_serial_read_pkt_too_big_data_1_chunk_1,  "Serial port read: unfragmented packet: pkt too big: data 1 chunk 1", sn);
    pt_add_test(test_smp_serial_read_pkt_too_big_data_chunk_1,  "Serial port read: unfragmented packet: pkt too big: data chunk 1", sn);

    pt_add_test(test_smp_serial_read_pkt_too_big_2,  "Serial port read: fragmented packet: pkt too big 2", sn);
    pt_add_test(test_smp_serial_read_pkt_too_big_fragmented,  "Serial port read: fragmented packet: too big, fragmented", sn);
    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked,  "Serial port read: fragmented packet: echo", sn);
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    init_serial_transport();

    pt_add_suite(suite_smp_serial);

    return pt_run();
}
