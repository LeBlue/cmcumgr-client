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
#include <assert.h>
#include <stdbool.h>

#include "utils.h"
#include "serial_port.h"
#include "crc16.h"
#include "base64.h"

#include "mgmt_hdr.h"

#include "byteordering.h"

#include "mcumgr-client/smp_transport.h"
#include "serial_port.h"
#include "mcumgr-client/smp_serial.h"

#define PRDBG 0
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

    if (transport->verbose) {
        fprintf(stderr, "Using transport opts: %s %d\n", sopts->port_name, sopts->speed);
    }

    flush_dev_console(hd->port);

    return rc;
}

void serial_transport_close(struct smp_transport *transport)
{
    struct smp_serial_handle *hd = get_handle(transport);

    port_close(hd->port);
}


#define MCUMGR_SHELL_HDR_PKT          0x0609
#define MCUMGR_SHELL_HDR_DATA         0x0414
#define MCUMGR_SHELL_MAX_FRAME        127

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


static int smp_pkt_check_crc(uint8_t *buf, size_t pktlen, int verbose)
{
    uint16_t crc_c;

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

    return datalen;
}

/**
 * @brief Check if the gathered fragments are a complete smp packet
 *
 * @param buf       The buffer with all fragment data
 * @param datalen   length of data in @p buf
 * @param verbose   whether to print output for user
 *
 * @retval 0        smp packet complete
 * @retval -EAGAIN  fragment(s) missing
 * @retval -EBADMSG more data than MGMT header length indicates (TODO)
 */
static int smp_check_complete(uint8_t *buf, size_t datalen, int verbose)
{
    DBG("Checking len: %d\n", (int)datalen);
    int rc = mgmt_header_len_check(buf, datalen);
    if (rc == -ENODATA) {
        DBG("Expecting more: %d\n", (int)(mgmt_header_get_len((void *)buf) - datalen));

        return -EAGAIN;
    } else if (rc == 0) {
        /* TODO: check if header length matches data length */

        if (verbose > 1) {
            ehexdump(buf, datalen, "RX SMP packet");
        }
        /* only data */
        return datalen;
    }
    /* TODO: can never reach here (hdr len != rxed len) */
    if (verbose > 1) {
        ehexdump(buf, datalen, "RX frag, bad mgmt header");
    }
    return -EBADMSG;
}

/**
 * @brief Find the EOF newline and calculate length
 *
 * @param buf      buffer with received data, SOF must be at offset 0
 * @param len      length of valid data in the @p buf
 * @return size_t  the calculated length. 0 if EOF was not found
 */
static size_t smp_read_frame_len(uint8_t *buf, size_t len)
{
    size_t off;

    for (off = 0; off < len; off++) {
        if (buf[off] == '\n') {
            return off + 1;
        }
    }
    return 0;
}

/**
 * @brief try finding the start of frame delimiter
 *
 * The function moves the frame data to the start of the buffer
 * if some data is found before the SOF delimiter. The data
 * before is discarded. Updates the @p prxoff to reflect the number
 * of bytes in the @p rxbuf after discarding.
 *
 * @param rxbuf       buffer with received data
 * @param prxoff      number of bytes in @p rxbuf before reading, will be updated
 * @param bytes_read  number of bytes read in the buffer
 * @return int        number of bytes in the buffer.
 */
static int smp_find_frame_start(uint8_t *rxbuf, size_t *prxoff, int bytes_read)
{
    DBG("Search SOF\n");
    size_t soffset;
    bool found_sof = false;

    if (!prxoff) {
        return -EINVAL;
    }

    size_t rxoff = *prxoff;

    for (soffset = 0; soffset < (rxoff + bytes_read - 1); ++soffset) {
        uint16_t sof = get_be16(rxbuf + soffset);
        if (MCUMGR_SHELL_HDR_PKT == sof || MCUMGR_SHELL_HDR_DATA == sof) {
            DBG("FRAME START: %04x\n", sof);
            found_sof = true;
            break;
        } else {
            DBG("not sof: %04x\n", sof);
        }

    }
    if (soffset) {
        /* move out everything (or everything before SOF delimiter) */
        if (!found_sof) {
            if (rxbuf[soffset] != BYTE1(MCUMGR_SHELL_HDR_PKT) && rxbuf[soffset] != BYTE1(MCUMGR_SHELL_HDR_DATA)) {
                ++soffset;
            }
        }
        bytes_read = bytes_read - soffset;

        memmove(rxbuf, rxbuf + soffset, rxoff + bytes_read);
        DBG("Discard: %d, RC end: %d\n", (int) soffset, (int)(rxoff + bytes_read));
    }
    *prxoff += bytes_read;
    if (!found_sof) {
        return -ENOMSG;
    }
    return 0;
}

/**
 * @brief Decode the packet lenth from a start of SMP packet frame
 *
 * @param rxbuf   Data received buffer at SOF, must have at least 6 valid bytes
 * @param decbuf  Buffer for decoded data. First data byte will be decoded/written here
 * @return int    the decoded packet length, or negative error code
 */
static int smp_read_pkt_len(uint8_t *rxbuf, uint8_t *decbuf)
{
    int drc;
    uint8_t pktlen_buf[5];
    uint8_t tmp[3];
    uint16_t pktlen = 0;

    /* decode pktlen only, frame offset 2 */
    memcpy(pktlen_buf, rxbuf + 2, 4);
    pktlen_buf[4] = '\0';

    drc = base64_decode((char*)pktlen_buf, tmp);
    pktlen = get_be16(tmp);
    DBG("SMP fragment len: %d\n", pktlen);

    /* save first decoded byte */
    if (drc > 2) {
        decbuf[0] = tmp[2];
        DBG("First byte: %02x\n", decbuf[0]);
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
    int clen;

    /* frames/chunks should not exceed 127 bytes */
    uint8_t rxbuf[MCUMGR_SHELL_MAX_FRAME];

    /* write offset in rxbuf */
    size_t rxoff = 0;
    /* write offset in bbuf */
    size_t boff = 0;
    /* current smp fragment */
    uint8_t *bbuf = buf;
    int have_frame_start = 0;

    /* frame fragement length, read from first frame */
    uint16_t fraglen = 0;
    uint16_t smp_len = 0;

    struct smp_serial_handle *hd = get_handle(transport);

    int tmo = transport->timeout;

    DBG("Read: maxlen: %zu\n", maxlen);

    now = time_get();
    end_time = now + tmo + 2;

    while (1) {
        /* read no more than buffers allow, and never more than one frame data
           TODO: does not really work. reading too much (and potentially discarding)
         */
        size_t readlen;
        if (!fraglen) {
            readlen = MIN_PACKET_LEN;
        } else if (rxoff >= sizeof(rxbuf)) {
            /* smp chunk too big */
            return -EPROTO;
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
        if (transport->verbose > 1) {
            ehexdump(rxbuf + rxoff, rc, "Port read");
        }

        if (!have_frame_start) {
            rc = smp_find_frame_start(rxbuf, &rxoff, rc);
            /* not found */
            DBG("Frame start returned: %d (readlen %d, off %d)\n", rc, (int)readlen, (int)rxoff);
            if (rc < 0) {
                continue;
            }
            have_frame_start = 1;
        } else {
            rxoff += rc;
        }
        DBG("New off: %zu\n", rxoff);
        assert(rxoff <= sizeof(rxbuf));

        /* enough bytes read that fraglen is decodeable */
        if (!fraglen && rxoff > 6) {
            if ((boff + 1) > maxlen) {
                DBG("SMP read buffer too small, len (%d), required: %d (+%d)\n", (int)maxlen, (int)(boff + 1), (int)smp_len);
                return -ENOBUFS;
            }
            rc = smp_read_pkt_len(rxbuf, bbuf + boff);
            if (rc < 0) {
                return rc;
            }
            fraglen = rc;
            if (fraglen < MGMT_HEADER_LEN) {
                return -EBADMSG;
            }
            boff++; /* first data byte is already decoded with the len */
        } else if (rxoff <= 6) {
            continue;
        }

        /* find offset of next newline */
        if ((clen = smp_read_frame_len(rxbuf, rxoff))) {
            /* Some bounds check failed, already overflowed */
            assert(clen <= (int)sizeof(rxbuf));

            if (transport->verbose > 1) {
                ehexdump(rxbuf, clen, "RX chunk");
            }

            rxbuf[clen - 1] = '\0'; /* replace newline */

            if (clen > 4) {
                int drc;
                uint16_t dec_len;
                uint16_t frame_start = get_be16(&rxbuf[0]);
                /* offset of start of base64 data in rxbuf */
                size_t soff;

                if (frame_start == MCUMGR_SHELL_HDR_PKT) {
                    dec_len = 1;
                    soff = sizeof(frame_start) + BASE64_ENCODE_SIZE(sizeof(fraglen));
                } else if (frame_start == MCUMGR_SHELL_HDR_DATA) {
                    dec_len = boff;
                    soff = sizeof(frame_start);
                } else {
                    return -EBADMSG;
                }

                /* make sure to not overflow out buf */
                drc = base64_decode_len((char*)&rxbuf[soff]);
                DBG("EST2 len: %d\n", (int)drc);

                if ((boff + drc) > maxlen) {
                    DBG("SMP read buffer too small, data (%d), required: %d (+%d)\n", (int)maxlen, (int)(boff + drc), (int)smp_len);
                    return -ENOBUFS;
                }

                drc = base64_decode((char*)&rxbuf[soff], bbuf + boff);
                DBG("REAL len: %d\n", (int)drc);

                /* decode data and potentially crc */
                if (drc < 0 || drc > UINT16_MAX) {
                    return -EBADMSG;
                }
                dec_len += drc;
                boff += drc;
                /* Some bounds check failed, already overflowed */
                assert(boff <= maxlen);

                DBG("Len pkt hdr: %d (+2?), len frag decoded: %d\n", fraglen, dec_len);
                if (transport->verbose > 1) {
                    ehexdump(bbuf, dec_len, "RX decoded");
                }

                /*  Workaround zephyr bug in serial smp, that does not include crc in length on response
                    Should be fixed in 3.0.0/2.7.2
                */
                if ((boff) == (size_t)(fraglen + 2)) {
                    DBG("zephyr bug Workaround\n");
                    fraglen += 2;
                }

                /* more data in frame than indicated */
                if (boff > fraglen) {
                    return -EBADMSG;
                }

                /* check if last fragment */
                if (fraglen && boff >= fraglen) {
                    rc = smp_pkt_check_crc(bbuf, fraglen, transport->verbose);
                    if (rc < 0) {
                        return rc;
                    }
                    /* Some bounds check failed, already overflowed */
                    assert((size_t)rc < maxlen);

                    smp_len += rc;
                    fraglen = rc;
                    rc = smp_check_complete(buf, smp_len, transport->verbose);

                    if (rc == -EAGAIN) {
                        /* reset for new fragement, save remaining data */
                        DBG("Expecting more SMP fragments\n");
                        if ((size_t) clen < rxoff) {
                            DBG("Saving %d bytes\n", (int)(rxoff - clen));
                            memmove(rxbuf, rxbuf + clen, (rxoff - clen));
                            rxoff -= clen;
                        } else {
                            rxoff = 0;
                        }
                        bbuf += fraglen;
                        boff = 0;
                        maxlen -= fraglen;
                        fraglen = 0;
                    } else {
                        DBG("FRAG len returned: %d\n", (int)smp_len);
                        return smp_len;
                    }
                } else {
                    DBG("Expect more data chunks\n");
                    /* chunk is smaller than default, non spec server. Save already rx'd bytes */
                    if ((size_t) clen < rxoff) {
                        DBG("Saving %d bytes\n", (int)(rxoff - clen));
                        memmove(rxbuf, rxbuf + clen, (rxoff - clen));
                        rxoff -= clen;
                    } else {
                        rxoff = 0;
                    }

                }
                have_frame_start = 0;
            }
        }
        DBG("Reread\n");
    }

    return rc;
}

static int serial_transport_get_mtu(struct smp_transport *t)
{
    (void)t;
    return 256;
}

static const struct smp_operations serial_transport_ops = {
    .open = serial_transport_connect,
    .read = serial_transport_read,
    .write = serial_transport_write,
    .close = serial_transport_close,
    .get_mtu = serial_transport_get_mtu,
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
