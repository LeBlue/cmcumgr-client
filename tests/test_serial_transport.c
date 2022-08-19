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

/* debug: set verbosity of transport (0/1/2) */
#define TRANSPORT_VERBOSE 0

/* simple way to 'comment' out some tests, set to 0 to disable */
#define TEST_WRITE 1
#define TEST_READ 1
#define TEST_READ_FRAG 1

struct serial_mock_state {
    uint8_t read_poll_wait;

    /* data that is read from port */
    uint8_t rx_buf[MOCK_BUF_SZ];
    size_t rx_off; /* current read offset */
    size_t rx_size; /* combined data size */

    size_t rx_chunk_len[MAX_CHUNKS]; /* length of each chunk */
    int rx_n_chunks; /* total number of chunks */
    int rx_chunk; /* current number */

    /* data that is written to port */
    uint8_t tx_buf[MOCK_BUF_SZ];
    size_t tx_off;
    size_t tx_chunk_len[MAX_CHUNKS];
    int tx_chunk;

    /* option to always return only one bytes (single step) */
    bool single_bytes;
};

static struct serial_mock_state serial_state = {0};
static int current_time = 0;

int time_get(void)
{
    /* 100 ms per call */
    if (serial_state.single_bytes) {
        current_time += 1;
    } else {
        current_time += 100;
    }
    return current_time/1000;
}

void mock_serial_port_init(void)
{
    current_time = 0;
    memset(&serial_state, 0, sizeof(serial_state));
}

void mock_serial_port_rewind(void)
{
    serial_state.rx_chunk = 0;
    serial_state.rx_off = 0;
    serial_state.tx_off = 0;
    memset(&serial_state.tx_buf, 0, sizeof(serial_state.tx_buf));
    serial_state.tx_chunk = 0;
    memset(&serial_state.tx_chunk_len, 0, sizeof(serial_state.tx_chunk_len));
}

void mock_serial_port_rewind_rx_single(void)
{
    mock_serial_port_rewind();
    serial_state.single_bytes = true;
}

/* avoid discards const warnings, need additional space also (crc): TODO: fix impl */
uint8_t *tx_copy_msg(const uint8_t *buf, size_t sz)
{
    uint8_t *new_buf = malloc(sz + 2);
    assert(new_buf);
    memcpy(new_buf, buf, sz);
    return new_buf;
}

void tx_free_msg(uint8_t *buf)
{
    free(buf);
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
    if (serial_state.rx_n_chunks >= MAX_CHUNKS) {
        /* abort test */
        fprintf(stderr, "Test ERROR: Static buffer too low for test: MAX_CHUNKS\n");
        assert(serial_state.rx_n_chunks < MAX_CHUNKS);
    }
    serial_state.rx_chunk_len[serial_state.rx_n_chunks++] = sz;

    if (sz && data) {
        memcpy(serial_state.rx_buf + serial_state.rx_size - sz, data, sz);
    }
}

#define RX_CHUNK(_data) \
    mock_add_rx_chunk(_data, sizeof(_data)/sizeof(_data[0]))

/* add to simulate data pause */
void mock_add_rx_empty_chunk(void) {
    mock_add_rx_chunk(NULL, 0);
}

/* helper to resplit the data that will be received, to make 'port_read'
   not align these properly. Usefull for rusing the same static data multiple
   times with different resulting read sizes */
void mock_rechunk_rx(size_t *chunk_lengths, int num_chunks)
{
    size_t dsize = 0;
    size_t new_size = 0;

    if (num_chunks >= MAX_CHUNKS) {
        /* abort test */
        fprintf(stderr, "Test ERROR: rechunking into too many: MAX_CHUNKS\n");
        assert(num_chunks < MAX_CHUNKS);
    }

    for (int i = 0; i < serial_state.rx_n_chunks; ++i) {
        dsize += serial_state.rx_chunk_len[i];
    }

    for (int i = 0; i < num_chunks; ++i) {
        new_size += chunk_lengths[i];
    }

    if ((new_size != dsize) || (new_size != serial_state.rx_size)) {
        fprintf(stderr, "Test ERROR: rechunking into different data size\n");
        assert(new_size == dsize);
        assert(new_size != serial_state.rx_size);
    }

    for (int i = 0; i < num_chunks; ++i) {
        serial_state.rx_chunk_len[i] = chunk_lengths[i];
    }
    serial_state.rx_n_chunks = num_chunks;
}

#define RX_CHUNK_RESPLIT(_data) \
    mock_rechunk_rx(_data, sizeof(_data)/sizeof(_data[0]))

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

        if (serial_state.single_bytes) {
            if (serial_state.rx_size == serial_state.rx_off) {
                return -ETIMEDOUT;
            } else {
                buf[0] = serial_state.rx_buf[serial_state.rx_off];
                ++serial_state.rx_off;
                return 1;
            }
        }

        /* no more data setup to read */
        if (serial_state.rx_chunk > serial_state.rx_n_chunks) {
            /* since original API waits until something rxed, simulate a timeout */
            return -ETIMEDOUT;
        }

        size_t chunk = serial_state.rx_chunk_len[serial_state.rx_chunk];

        if (chunk > 0) {
            if (chunk > maxlen) {
                chunk = maxlen;
                serial_state.rx_chunk_len[serial_state.rx_chunk] -= maxlen;
            } else {
                serial_state.rx_chunk++;
            }
            memcpy(buf, serial_state.rx_buf + serial_state.rx_off, chunk);
            serial_state.rx_off += chunk;
            return chunk;
        } else {
            serial_state.rx_chunk++;
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
        fprintf(stderr, "Test ERROR: Failed to init transport\n");
        exit(EXIT_FAILURE);
    }
    if (transport.ops->open(&transport)) {
        fprintf(stderr, "Test ERROR: Failed to open transport\n");
        exit(EXIT_FAILURE);
    }
    transport.verbose = TRANSPORT_VERBOSE;
}

#if TEST_WRITE

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

    tx_free_msg(tx_data);
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

    tx_free_msg(tx_data);
}

static void test_smp_serial_write_one_chunk_1(void)
{
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 256 */
	/* Full SMP packet */
	const uint8_t tx_data_const[88] =
		"\x03\x00\x00\x50\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x4b\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345";

	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AFoDAABQAAAAAKFh"
		"cnhLMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1eEc=" "\x0a";


    size_t tx_len = sizeof(tx_data_const);
    uint8_t *tx_data = tx_copy_msg(tx_data_const, tx_len);

    mock_serial_port_init();

    int rc = transport.ops->write(&transport, tx_data, tx_len);

    PT_ASSERT(rc == 0);
    PT_ASSERT(serial_state.tx_off == sizeof(chunk_0_0));
    PT_ASSERT_MEM_EQ(serial_state.tx_buf, chunk_0_0, sizeof(chunk_0_0));

    tx_free_msg(tx_data);
}

static void test_smp_serial_write_one_chunk_2(void)
{
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 256 */
	/* Full SMP packet */
	const uint8_t tx_data_const[89] =
		"\x03\x00\x00\x51\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x4c\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"6";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AFsDAABRAAAAAKFh"
		"cnhMMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Nvfp" "\x0a";



    size_t tx_len = sizeof(tx_data_const);
    uint8_t *tx_data = tx_copy_msg(tx_data_const, tx_len);

    mock_serial_port_init();

    int rc = transport.ops->write(&transport, tx_data, tx_len);

    PT_ASSERT(rc == 0);
    PT_ASSERT(serial_state.tx_off == sizeof(chunk_0_0));
    PT_ASSERT_MEM_EQ(serial_state.tx_buf, chunk_0_0, sizeof(chunk_0_0));

    tx_free_msg(tx_data);
}


static void test_smp_serial_write_two_chunk(void)
{
	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   max fragment size: 256 */
	/* Full SMP packet */
	const uint8_t tx_data_const[90] =
		"\x03\x00\x00\x52\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\x4d\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"67";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AFwDAABSAAAAAKFh"
		"cnhNMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc0" "\x0a";
	/* SMP serial fragment 0 chunk: 1 */
	const uint8_t chunk_0_1[7] =
		"\x04\x14"
		"IA==" "\x0a";

    size_t tx_len = sizeof(tx_data_const);
    uint8_t *tx_data = tx_copy_msg(tx_data_const, tx_len);
    size_t tx_total = sizeof(chunk_0_0) + sizeof(chunk_0_1);
    size_t tx_off = 0;


    mock_serial_port_init();

    int rc = transport.ops->write(&transport, tx_data, tx_len);

    PT_ASSERT(rc == 0);
    PT_ASSERT(serial_state.tx_off == tx_total);
    PT_ASSERT_MEM_EQ(serial_state.tx_buf + tx_off, chunk_0_0, sizeof(chunk_0_0));
    tx_off += sizeof(chunk_0_0);

    PT_ASSERT_MEM_EQ(serial_state.tx_buf + tx_off, chunk_0_1, sizeof(chunk_0_1));

    tx_free_msg(tx_data);
}


static void test_smp_serial_write_long(void)
{

	/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
	   payload
	   {'r': '123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123'}
	   max fragment size: 256 */
	/* Full SMP packet */
	const uint8_t exp_rx_data[256] =
		"\x03\x00\x00\xf8\x00\x00\x00\x00"
		"\xa1\x61\x72\x78\xf3\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"6789012345678901"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"6789012345678901"
		"2345678901234567"
		"8901234567890123"
		"4567890123456789"
		"0123456789012345"
		"67890123";
	/* SMP serial fragment 0 chunk: 0 */
	const uint8_t chunk_0_0[127] =
		"\x06\x09"
		"AQIDAAD4AAAAAKFh"
		"cnjzMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4" "\x0a";
	/* SMP serial fragment 0 chunk: 1 */
	const uint8_t chunk_0_1[127] =
		"\x04\x14"
		"OTAxMjM0NTY3ODkw"
		"MTIzNDU2Nzg5MDEy"
		"MzQ1Njc4OTAxMjM0"
		"NTY3ODkwMTIzNDU2"
		"Nzg5MDEyMzQ1Njc4"
		"OTAxMjM0NTY3ODkw"
		"MTIzNDU2Nzg5MDEy"
		"MzQ1Njc4OTAx" "\x0a";
	/* SMP serial fragment 0 chunk: 2 */
	const uint8_t chunk_0_2[103] =
		"\x04\x14"
		"MjM0NTY3ODkwMTIz"
		"NDU2Nzg5MDEyMzQ1"
		"Njc4OTAxMjM0NTY3"
		"ODkwMTIzNDU2Nzg5"
		"MDEyMzQ1Njc4OTAx"
		"MjM0NTY3ODkwMTIz"
		"OaI=" "\x0a";

    size_t tx_len = sizeof(exp_rx_data);
    uint8_t *tx_data = tx_copy_msg(exp_rx_data, tx_len);
    size_t tx_total = 0;
    size_t tx_off = 0;

    mock_serial_port_init();

    int rc = transport.ops->write(&transport, tx_data, tx_len);

    PT_ASSERT(rc == 0);
    tx_total += sizeof(chunk_0_0);
    tx_total += sizeof(chunk_0_1);
    tx_total += sizeof(chunk_0_2);

    PT_ASSERT(serial_state.tx_off == tx_total);

    PT_ASSERT_MEM_EQ(serial_state.tx_buf + tx_off, chunk_0_0, sizeof(chunk_0_0));
    tx_off += sizeof(chunk_0_0);

    PT_ASSERT_MEM_EQ(serial_state.tx_buf + tx_off, chunk_0_1, sizeof(chunk_0_1));
    tx_off += sizeof(chunk_0_1);

    PT_ASSERT_MEM_EQ(serial_state.tx_buf + tx_off, chunk_0_2, sizeof(chunk_0_2));
    tx_off += sizeof(chunk_0_2);

    tx_free_msg(tx_data);
}

#endif /* TEST_WRITE */

#if TEST_READ

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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

    RX_CHUNK(rx_enc_data);

    uint8_t rbuf[128];
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == -ETIMEDOUT);
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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
    RX_CHUNK(garbage1);
    RX_CHUNK(garbage2);
    RX_CHUNK(rx_enc_data);

    uint8_t rbuf[128];
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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

    RX_CHUNK(rx_enc_data1);
    RX_CHUNK(rx_enc_data2);

    uint8_t rbuf[128];
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(exp_rx_data));
    PT_ASSERT_MEM_EQ(exp_rx_data, rbuf, sizeof(exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc == sizeof(smp2big_exp_rx_data));
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
    PT_ASSERT_MEM_EQ(smp2big_exp_rx_data, rbuf, sizeof(smp2big_exp_rx_data));

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

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
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
}


static void test_smp_serial_read_pkt_too_big_oneless(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = sizeof(smp2big_exp_rx_data) - 1 + 2; /* tested buffer size, +2 for crc needed */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
}


static void test_smp_serial_read_pkt_too_big_data_1_chunk_0(void)
{
    /* not enough buf space to decode data 1. byte */
    size_t buflen = 0; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
}


static void test_smp_serial_read_pkt_too_big_data_chunk_0(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = 93; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
}


static void test_smp_serial_read_pkt_too_big_data_1_chunk_1(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = sizeof(smp2big_exp_rx_data) - 1; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
}


static void test_smp_serial_read_pkt_too_big_data_chunk_1(void)
{
    /* almost enough buf space. (-1 byte) */
    size_t buflen = sizeof(smp2big_exp_rx_data) - 1; /* tested buffer size */

    mock_serial_port_init();

    RX_CHUNK(smp2big_chunk_0_0);
    RX_CHUNK(smp2big_chunk_0_1);

    uint8_t rbuf[251]; /* make big for copy+paste test */
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf)); /* add sentinel value, reserve 1 byte for overflow checking */

    rc = transport.ops->read(&transport, rbuf, buflen);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[buflen] == 0xaa); /* check for overflow */
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
    int rc;
    memset(rbuf, 0xaa, sizeof(exp_rx_data));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[sizeof(exp_rx_data) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(exp_rx_data));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[sizeof(exp_rx_data) - 1] == 0xaa);

}

#endif /* TEST_READ */

#if TEST_READ_FRAG

/* fragmented packet means the response is fragemnted on mcumgr layer */
/* MgmtHeader(op:MgmtOp.WRITE_RSP group:MgmtGroup.OS id:0 len:0 seq:0 flags:0)
    max fragment size: 100 */
/* Full SMP packet */
const uint8_t frag_exp_rx_data[133] =
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
const uint8_t frag_chunk_0_0[127] =
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
const uint8_t frag_chunk_0_1[19] =
    "\x04\x14"
    "OTAxMjM0NTY3mdg="
    "" "\x0a";
/* SMP serial fragment 1 chunk: 0 */
const uint8_t frag_chunk_1_0[55] =
    "\x06\x09"
    "ACM4OTAxMjM0NTY3"
    "ODkwMTIzNDU2Nzg5"
    "MDEyMzQ1Njc4OTDx"
    "8g==" "\x0a";


/* some interspersed log message */
const uint8_t log_msg[69] =
    "[00:00:00] <inf> some log message\n"
    "[02:02:02] <inf> some log message2\n";


static void test_smp_serial_read_pkt_too_big_fragmented(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
	mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(frag_chunk_1_0);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1 - 1];
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc != 0);
    PT_ASSERT(rc == -ENOBUFS);
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_fragmented_pkt_chunked(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
    mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(frag_chunk_1_0);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1];
    int rc;

    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_fragmented_pkt_chunked_split_read_1(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer
       additionally make port not receive on chunks/fragment boundaries */
    mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(frag_chunk_1_0);

    /* receive just one stream */
    size_t rxsplit[] = {
        sizeof(frag_chunk_0_0) + sizeof(frag_chunk_0_1) + sizeof(frag_chunk_1_0),
    };
    RX_CHUNK_RESPLIT(rxsplit);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1];
    int rc;

    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_fragmented_pkt_chunked_split_read_1_wlog(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer
       additionally make port not receive on chunks/fragment boundaries */
    mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(log_msg);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(log_msg);
    RX_CHUNK(frag_chunk_1_0);
    RX_CHUNK(log_msg);

    /* receive just one stream */
    size_t rxsplit[] = {
        sizeof(frag_chunk_0_0) + sizeof(frag_chunk_0_1) + sizeof(frag_chunk_1_0) + 3*sizeof(log_msg),
    };
    RX_CHUNK_RESPLIT(rxsplit);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1];
    int rc;

    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_fragmented_pkt_chunked_split_read_2(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
    mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(frag_chunk_1_0);

    size_t rxsplit[] = {
        sizeof(frag_chunk_0_0),
        sizeof(frag_chunk_0_1) + 2, /* receive next 2 bytes (SOF) early */
        sizeof(frag_chunk_1_0) - 2,
    };
    RX_CHUNK_RESPLIT(rxsplit);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1];
    int rc;

    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}


static void test_smp_serial_read_fragmented_pkt_chunked_split_read_2_wlog(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
    mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(log_msg);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(log_msg);
    RX_CHUNK(frag_chunk_1_0);
    RX_CHUNK(log_msg);

    size_t rxsplit[] = {
        sizeof(frag_chunk_0_0) + sizeof(log_msg),
        sizeof(frag_chunk_0_1) + sizeof(log_msg) + 2, /* receive next 2 bytes (SOF) early */
        sizeof(frag_chunk_1_0) + sizeof(log_msg) - 2,
    };
    RX_CHUNK_RESPLIT(rxsplit);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1];
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));

    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_fragmented_pkt_chunked_split_read_3(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
    mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(frag_chunk_1_0);

    size_t rxsplit[] = {
        sizeof(frag_chunk_0_0),
        sizeof(frag_chunk_0_1) + 1, /* receive partial next SOF early */
        sizeof(frag_chunk_1_0) - 1,
    };
    RX_CHUNK_RESPLIT(rxsplit);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1];
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

static void test_smp_serial_read_fragmented_pkt_chunked_split_read_3_wlog(void)
{
    /* fragmented packet means the response is fragemnted on mcumgr layer */
    mock_serial_port_init();

    RX_CHUNK(frag_chunk_0_0);
    RX_CHUNK(log_msg);
    RX_CHUNK(frag_chunk_0_1);
    RX_CHUNK(log_msg);
    RX_CHUNK(frag_chunk_1_0);
    RX_CHUNK(log_msg);

    size_t rxsplit[] = {
        sizeof(frag_chunk_0_0) + sizeof(log_msg) + 1,  /* receive partial next SOF early */
        sizeof(frag_chunk_0_1) + sizeof(log_msg),      /* receive partial next SOF early */
        sizeof(frag_chunk_1_0) + sizeof(log_msg) - 1,
    };
    RX_CHUNK_RESPLIT(rxsplit);

    uint8_t rbuf[sizeof(frag_exp_rx_data) + 2 + 1];
    int rc;
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);

    /* same test with single rx'd bytes */
    mock_serial_port_rewind_rx_single();
    memset(rbuf, 0xaa, sizeof(rbuf));
    rc = transport.ops->read(&transport, rbuf, sizeof(rbuf) - 1);

    PT_ASSERT(rc == sizeof(frag_exp_rx_data));
    PT_ASSERT_MEM_EQ(frag_exp_rx_data, rbuf, sizeof(frag_exp_rx_data));
    PT_ASSERT(rbuf[sizeof(rbuf) - 1] == 0xaa);
}

#endif /* TEST_READ_FRAG */


static void suite_smp_serial_write(void)
{
    const char *sn =  "Suite SMP serial transport write";

    pt_add_test(test_smp_serial_write_hello, "Serial port write: Hello", sn);
    pt_add_test(test_smp_serial_write_mgmt_rc, "Serial port write: MGMT RC", sn);
    pt_add_test(test_smp_serial_write_one_chunk_1, "Serial port write: One chunk 1", sn);
    pt_add_test(test_smp_serial_write_one_chunk_2, "Serial port write: One chunk 2", sn);
    pt_add_test(test_smp_serial_write_two_chunk, "Serial port write: Two chunk", sn);
    pt_add_test(test_smp_serial_write_long, "Serial port write: Long fragmenterd/chunked", sn);
}

#if TEST_READ
static void suite_smp_serial_read(void)
{
    const char *sn =  "Suite SMP serial transport read";

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
}
#endif

#if TEST_READ_FRAG
static void suite_smp_serial_read_fragmented(void)
{
    const char *sn =  "Suite SMP serial transport read fragmented";

    pt_add_test(test_smp_serial_read_pkt_too_big_2,  "Serial port read: fragmented packet: pkt too big 2", sn);
    pt_add_test(test_smp_serial_read_pkt_too_big_fragmented,  "Serial port read: fragmented packet: too big, fragmented", sn);
    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked,  "Serial port read: fragmented packet: echo", sn);

    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked_split_read_1, "Serial port read: fragmented packet: uneven read 1", sn);
    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked_split_read_1_wlog, "Serial port read: fragmented packet: uneven read 1 w/ log", sn);
    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked_split_read_2, "Serial port read: fragmented packet: uneven read 2", sn);
    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked_split_read_2_wlog, "Serial port read: fragmented packet: uneven read 2 w/log", sn);
    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked_split_read_3, "Serial port read: fragmented packet: uneven read 3", sn);
    pt_add_test(test_smp_serial_read_fragmented_pkt_chunked_split_read_3_wlog, "Serial port read: fragmented packet: uneven read 3 w/log", sn);

}
#endif

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    init_serial_transport();

#if TEST_WRITE
    pt_add_suite(suite_smp_serial_write);
#endif
#if TEST_READ
    pt_add_suite(suite_smp_serial_read);
#endif
#if TEST_READ_FRAG
    pt_add_suite(suite_smp_serial_read_fragmented);
#endif
    return pt_run();
}
