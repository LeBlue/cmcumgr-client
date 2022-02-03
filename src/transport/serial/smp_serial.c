/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "utils.h"
#include "serial_port.h"
#include "crc16.h"
#include "base64.h"

#include "mgmt_hdr.h"

#include "file_reader_unix.h"
#include "byteordering.h"


#include "smp_transport.h"
#include "serial_port.h"
#include "smp_serial.h"

#define PRDBG 1
#if PRDBG
#include <stdio.h>
#define DBG(fmt, args...) do { fprintf(stderr, "dbg: " fmt, ##args); } while (0)
#else
#define DBG(fmt, args...) do {} while (0)
#endif


static inline struct smp_serial_handle *get_handle(struct smp_transport *transport)
{
    struct smp_serial_handle *hd = (struct smp_serial_handle *) transport->hd;
    return hd;
}

static int port_read_frame_len(uint8_t *buf, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            return i + 1;
        }
    }
    return 0;
}

static void flush_dev_console(HANDLE port)
{
    port_write_data(port, "\n", 1);
}

int serial_transport_connect(struct smp_transport *transport)
{
    struct smp_serial_handle *hd = get_handle(transport);
    struct serial_opts *sopts = &hd->opts;

    int rc;
    int fd = port_open(sopts->port_name);
    if (fd < 0) {
        return -1;
    }


    hd->port = fd;

    rc = port_setup(hd->port, sopts->speed);
    if (rc < 0) {
        fprintf(stderr, "Failed to setup port %s %d\n", sopts->port_name, sopts->speed);
    }

    fprintf(stderr, "Using transport opts: %s %d\n", sopts->port_name, sopts->speed);

    flush_dev_console(hd->port);

    return rc;
}

void serial_transport_close(struct smp_transport *transport)
{
    struct smp_serial_handle *hd = get_handle(transport);

    close(hd->port);
}


#define MCUMGR_SHELL_HDR_PKT          0x0609
#define MCUMGR_SHELL_HDR_DATA         0x0414
#define MCUMGR_SHELL_MAX_FRAME        128

#define BYTE1(_num) ((uint8_t)(((_num) >> 8) & 0xff))
#define SOF_BITS ((uint8_t)(BYTE1(MCUMGR_SHELL_HDR_DATA) | BYTE1(MCUMGR_SHELL_HDR_PKT)))

#define MAYBE_FRAME_START(_byte) (((uint8_t)(~(SOF_BITS)) ^ (_byte)) & SOF_BITS)

#define TMP_BUF_SZ 512

int serial_transport_write(struct smp_transport *transport, uint8_t *buf, size_t len)
{
    uint16_t crc;
    size_t off = 0;
    size_t boff;
    size_t blen;
    /* encoded frame */
    uint8_t enc_tmpbuf[TMP_BUF_SZ];

    struct smp_serial_handle *hd = get_handle(transport);

    /* append crc */
    crc = crc16_ccitt(CRC16_INITIAL_CRC, buf, len);
    /* TODO: discards const */
    set_be16(buf + len, crc);
    len += sizeof(crc);

    if (transport->verbose > 1) {
        ehexdump(buf, len, "TX unencoded");
    }

    while (off < len) {
        if (off == 0) {
            uint8_t pkt_len_buf[3];
            /* write frame start marker, not base64 */
            set_be16(enc_tmpbuf, MCUMGR_SHELL_HDR_PKT);
            DBG("len: %zu\n", len);
            set_be16(pkt_len_buf, len);
            pkt_len_buf[2] = buf[0]; /* add first data byte, base64 encoding needs 3 */
            boff = 2;
            off = 1;
            /* base64 encoded data starts after frame marker */
            boff += base64_encode(pkt_len_buf, 3, (char*)&enc_tmpbuf[2], 0);
            /* remaining len */
            blen = 90;
        } else {
            set_be16(enc_tmpbuf, MCUMGR_SHELL_HDR_DATA);
            boff = 2;
            blen = 93;
        }

        if (blen > len - off) {
            blen = len - off;
        }
        boff += base64_encode(&buf[off], blen, (char*)&enc_tmpbuf[boff], 1);
        off += blen;
        enc_tmpbuf[boff++] = '\n';

        if (transport->verbose > 1) {
            ehexdump(enc_tmpbuf, boff, "TX encoded");
        }
	    if (port_write_data(hd->port, enc_tmpbuf, boff) < 0) {
            return -1;
        }
    }

    return 0;
}


static int smp_pkt_check_crc(uint8_t *buf, size_t pktlen, int verbose) {
    uint16_t crc_c;
    ehexdump(buf, pktlen, "CRC of");

    crc_c = crc16_ccitt(CRC16_INITIAL_CRC, buf, pktlen);
    if (verbose) {
        uint16_t crc;
        crc = get_be16(&buf[pktlen - sizeof(crc)]);
        fprintf(stderr, "CRC rcv: %x\n", crc);
        fprintf(stderr, "CRC calc: %x\n", crc16_ccitt(CRC16_INITIAL_CRC, buf, pktlen - sizeof(crc)));
    }
    if (crc_c) {
        return -EBADMSG;
    }
    DBG("CRC:OK\n");

    size_t datalen = pktlen - sizeof(crc_c);
    /* smp pkt starts at offset, after pktlen field */
    /* TODO: remove check and return data? Length/crc/framing are correct here */
    if (mgmt_header_is_rsp_complete(buf, datalen)) {

        if (verbose > 1) {
            ehexdump(buf, datalen, "RX frag");
        }
        /* only data */
        return datalen;
    }
    if (verbose > 1) {
        ehexdump(buf, datalen, "RX frag, bad mgmt header");
    }
    return -EBADMSG;
}

static int smp_find_frame_start(uint8_t *rxbuf, size_t rxoff, int bytes_read)
{
    DBG("Search SOF\n");
    size_t soffset;
    for (soffset = 0; soffset < (rxoff + bytes_read - 1); ++soffset) {
        uint16_t sof = get_be16(rxbuf + soffset);
        if (MCUMGR_SHELL_HDR_PKT == sof || MCUMGR_SHELL_HDR_DATA == sof) {
            DBG("FRAME START: %04x\n", sof);
            break;
        } else {
            DBG("not sof: %04x\n", sof);
        }

    }
    if (soffset) {
        /* move out everything (or everything before SOF delimiter) */
        bytes_read = bytes_read - soffset;

        memmove(rxbuf, rxbuf + soffset, rxoff + bytes_read);
        DBG("Discard: %d, RC end: %d\n", (int) soffset, (int)(rxoff + bytes_read));
    }
    ehexdump(&rxbuf[0], rxoff + bytes_read, "RX read");
    return bytes_read;
}

/**
 * @brief Decode the packet lenth from a start of SMP packet frame
 *
 * @param rxbuf   data received buffer,
 * @param decbuf
 * @return int
 */
static int smp_read_pkt_len(uint8_t *rxbuf, uint8_t *decbuf)
{
    int drc;
    uint8_t pktlen_buf[5];
    uint16_t pktlen = 0;

    /* decode pktlen only, frame offset 2 */
    memcpy(pktlen_buf, rxbuf + 2, 4);
    pktlen_buf[4] = '\0';

    ehexdump(pktlen_buf, 4, "PKTLEN");

    drc = base64_decode((char*)pktlen_buf, decbuf);
    pktlen = get_be16(decbuf);
    DBG("SMP pkt len: %d\n", pktlen);

    /* save first decoded byte */
    if (drc > 2) {
        decbuf[0] = decbuf[2];
        DBG("Extra: %02x\n", decbuf[0]);
    } else {
        return -EBADMSG;
    }
    return pktlen;
}


#define MIN_PACKET_LEN (BASE64_ENCODE_SIZE(MGMT_HEADER_LEN + 4) + 3)

static int serial_transport_read(struct smp_transport *transport, uint8_t *buf, size_t maxlen)
{
    int end_time, now;
    int rc;
    int len;

    // uint8_t rxbuf[TMP_BUF_SZ];
    /* frames should not exceed 127 bytes */
    // uint8_t rxbuf[128];
    uint8_t rxbuf[127];

    /* write offset in rxbuf */
    size_t rxoff = 0;
    /* offset of start of frame in rxbuf */
    size_t soff = 0;
    /* write offset in buf */
    size_t boff = 0;

    /* frame/packet length, read from first frame */
    uint16_t pktlen = 0;

    struct smp_serial_handle *hd = get_handle(transport);

    int tmo = transport->timeout;

    transport->verbose = 2;

    DBG("Read: maxlen: %zu\n", maxlen);

    now = time_get();
    end_time = now + tmo + 2;

    while (1) {
        if (soff == rxoff) {
            soff = rxoff = 0;
        }
        /* read no more than buffers allow, and never more than one frame data */
        size_t readlen;
        if (!pktlen) {
            readlen = MIN_PACKET_LEN;
        } else {
            readlen = sizeof(rxbuf) - rxoff;
        }

        DBG("port read off: %zu, len: %zu\n", rxoff, readlen);
        rc = port_read_poll(hd->port, (char*)&rxbuf[rxoff], readlen, end_time,
                            transport->verbose);

        DBG("Read #bytes start: %d\n", rc);

        if (rc < 0) {
            break;
        }
        ehexdump(&rxbuf[rxoff], rc, "RXed");

        if (rxoff < 2) {
            rc = smp_find_frame_start(rxbuf, rxoff, rc);
        }
        rxoff += rc;
        DBG("New off: %zu\n", rxoff);

        if (!pktlen && rxoff > 6) {
            rc = smp_read_pkt_len(rxbuf, buf);
            if (rc < 0) {
                return rc;
            }
            pktlen = rc;
            boff++;
        }

        /* find offset of next newline */
        if ((len = port_read_frame_len(rxbuf, rxoff))) {
            if (transport->verbose > 1) {
                ehexdump(rxbuf, len, "RX frag");
            }
            rxbuf[len] = '\0'; /* replace newline */

            if (len > 4) {
                int drc;
                uint16_t dec_len = 1;

                assert(soff + len < maxlen);
                assert(maxlen > boff);

                uint16_t frame_start = get_be16(&rxbuf[0]);

                if (frame_start == MCUMGR_SHELL_HDR_PKT) {
                    dec_len = 1;
                    soff = sizeof(frame_start) + BASE64_ENCODE_SIZE(sizeof(pktlen));
                    drc = base64_decode((char*)&rxbuf[soff], buf + boff);

                } else if (frame_start == MCUMGR_SHELL_HDR_DATA) {
                    dec_len = boff;
                    soff = sizeof(frame_start);

                    ehexdump(rxbuf, len, "RX frag");

                    drc = base64_decode((char*)&rxbuf[soff], buf + boff);

                } else {
                    return -EBADMSG;
                }
                /* make sure to not overflow buf */
                // drc = base64_decode_len((char*)&rxbuf[soff + sizeof(pktlen)]);

                // if (drc < 2) {
                //     return -EBADMSG;
                // } else if ((size_t) drc > (maxlen - boff)) { /* TODO: account for fragmentation */
                //     return -ENOBUFS;
                // }

                /* decode data and potentially crc */
                if (drc < 0 || drc > UINT16_MAX) {
                    return -EBADMSG;
                }
                dec_len += drc;
                boff += drc;

                if (transport->verbose > 1) {
                    ehexdump(buf, dec_len, "RX decoded");
                    DBG("Len pkt hdr: %d (+2?), len frag: %d\n", pktlen, dec_len);
                }

                /*  Workaround zephyr bug in serial smp, that does not include crc in length on response
                    Should be fixed in 3.0.0/2.7.2
                */
                if ((boff) == (size_t)(pktlen + 2)) {
                    DBG("zephyr bug Workaround\n");
                    pktlen += 2;
                }

                /* more data in frame than indicated */
                if (boff > pktlen) {
                    return -EBADMSG;
                }

                /* check if last fragment */
                if (pktlen && boff == pktlen) {
                    return smp_pkt_check_crc(buf, pktlen, transport->verbose);
                } else {
                    DBG("Expect more data fragments\n");
                }
            }
            DBG("Frame completed\n");
            rxoff = 0;
            // soff += len;
        }
        DBG("Reread\n");
    }

    return rc;
}


#include "smp_transport.h"
static const struct smp_operations serial_transport_ops = {
    .open = serial_transport_connect,
    .read = serial_transport_read,
    .write = serial_transport_write,
    .close = serial_transport_close,
};


int serial_transport_init(struct smp_transport *transport, struct smp_serial_handle *hd, struct serial_opts *sopts)
{
    if (!transport || !hd || !sopts) {
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    memset(hd, 0, sizeof(*hd));

    transport->ops = &serial_transport_ops;
    transport->hd = (struct smp_handle*) hd;

    hd->opts = *sopts;

    return 0;
}
