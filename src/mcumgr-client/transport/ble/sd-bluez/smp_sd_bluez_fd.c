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
#include <error.h>
// #include <time.h>
#include <sys/time.h>
#include <fcntl.h>


#include <systemd/sd-bus.h>

#include "utils.h"

#include "mgmt_hdr.h"

#include "byteordering.h"

#include "sd_bluez.h"

#include <assert.h>


static int get_notify_fd(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_error sderr = SD_BUS_ERROR_NULL;
    uint16_t mtu;
    int fd;

    DBG("Call: %s %s %s %s\n", BLUEZ, path, IF_CHAR, "AcquireNotify");
    rc = sd_bus_call_method(hd->bus, BLUEZ, path, IF_CHAR, "AcquireNotify", &sderr, &msg, "a{sv}", 0, NULL);

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (sderr.message) {
            fprintf(stderr, "Failed to connect: %s\n", sderr.message);
        }
        goto cleanup;

        return rc;
    } else {
        rc = 0;
    }

    rc = sd_bus_message_read(msg, "hq", &fd, &mtu);

    if (rc < 0) {
        goto cleanup;
    } else {
        rc = 0;
        hd->nfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (hd->nfd < 0) {
            int err = errno;
            fprintf(stderr, "Err dup: %s\n", strerror(err));
            rc = -err;
        }
        DBG("MTU notify: %d, fd: %d, dupfd: %d\n", mtu, fd, hd->nfd);
    }

cleanup:
    sd_bus_message_unref(msg);
    return rc;
}

static int get_write_fd(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_error sderr = SD_BUS_ERROR_NULL;
    uint16_t mtu;
    int fd;

    DBG("Call: %s %s %s %s\n", BLUEZ, path, IF_CHAR, "AcquireWrite");
    rc = sd_bus_call_method(hd->bus, BLUEZ, path, IF_CHAR, "AcquireWrite", &sderr, &msg, "a{sv}", 0, NULL);

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (sderr.message) {
            fprintf(stderr, "Failed to AcquireWrite: %s\n", sderr.message);
        }
        goto cleanup;
    } else {
        rc = 0;
    }
    rc = sd_bus_message_read(msg, "hq", &fd, &mtu);

    if (rc < 0) {
        goto cleanup;
    } else {
        rc = 0;
        hd->mtu = mtu;
        hd->wfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (hd->wfd < 0) {
            int err = errno;
            fprintf(stderr, "Err dup: %s\n", strerror(err));
            rc = -err;
        }
        DBG("MTU write: %d, fd: %d, dupfd: %d\n", mtu, fd, hd->wfd);
    }

cleanup:
    sd_bus_message_unref(msg);

    return rc;
}

int sd_bluez_fd_transport_connect(struct smp_transport *transport)
{
    if (!transport) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);
    if (!hd) {
        return -EINVAL;
    }

    struct sd_bluez_opts *sopts = &hd->opts;
    int rc = 0;

    rc = sd_bus_default_system(&hd->bus);
    if (!rc) {
        return rc;
    }

    if (transport->verbose) {
        fprintf(stderr, "Using transport opts: %s\n", sopts->mcumgr_char);
    }

    rc = sd_bluez_connect_device(hd, hd->dev_path);
    if (rc < 0) {
        return rc;
    }

    rc = sd_bluez_check_smp_uuid(hd, hd->opts.mcumgr_char);
    if (rc < 0) {
        return rc;
    }

    rc = get_notify_fd(hd, hd->opts.mcumgr_char);
    if (rc) {
        return rc;
    }

    rc = get_write_fd(hd, hd->opts.mcumgr_char);
    if (rc) {
        return rc;
    }

    return rc;
}


#define TMP_BUF_SZ 512

int sd_bluez_fd_transport_write(struct smp_transport *transport, uint8_t *buf, size_t len)
{
    DBG("Write: transport: %p, buf: %p, len: %d\n", transport, buf, (int)len);

    if (!transport || !buf || !len) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);

    DBG("hd: %p, wfd: %d\n", hd, hd->wfd ? hd->wfd : -2);

    if (!hd || hd->wfd < 0) {
        return -EINVAL;
    }

    if (len > (size_t) (hd->mtu - 3)) {
        return -E2BIG;
    }

    ssize_t cnt = write(hd->wfd, buf, len);
    if (cnt < 0) {
        int err = errno;
        fprintf(stderr, "Failed to write: %s\n", strerror(err));
        return -err;
    } else {
        DBG("Written %d bytes\n", (int) cnt);
    }

    return 0;
}


static int time_now(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return tv.tv_sec;
}


static int sd_bluez_fd_transport_read(struct smp_transport *transport, uint8_t *buf, size_t maxlen)
{
    int rc = 0;
    size_t readlen = maxlen;
    uint8_t *readbuf = buf;

    DBG("Read\n");

    if (!transport || !buf || !maxlen) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);

    if (!hd || hd->nfd < 0) {
        return -EINVAL;
    }

    DBG("Read, args OK\n");

    int tmo = transport->timeout;

    DBG("Read: tmo: %d, maxlen: %d\n", tmo, (int)readlen);

    int end_time = time_now() + tmo + 2;

    while (readlen > 0) {

        int now = time_now();
        if (now > end_time) {
            fprintf(stderr, "Read timed out\n");
            return -ETIMEDOUT;
        }
        /* TODO: use poll */
        ssize_t cnt = read(hd->nfd, readbuf, readlen);
        if (cnt < 0) {
            int err = errno;
            if (err == EAGAIN || (EAGAIN != EWOULDBLOCK && err == EAGAIN)) {

            } else {
                fprintf(stderr, "Failed to read: %d, %s\n", err, strerror(err));
                return -err;
            }
        } else if (cnt > 0) {
            readlen -= cnt;
            readbuf += cnt;
            if (mgmt_header_is_rsp_complete(buf, maxlen - readlen)) {
                DBG("Complete\n");
                return maxlen - readlen;
            }
            DBG("Read, %d\n", (int) (maxlen - readlen));
        } else {
            DBG("Read 0\n");
            return -ETIMEDOUT;
        }
    }

    DBG("Read, %d\n", (int) (maxlen - readlen));

    return rc;
}

static void sd_bluez_fd_transport_close(struct smp_transport *transport)
{
    if (!transport) {
        return;
    }

    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);

    if (hd->wfd >= 0) {
        close(hd->wfd);
    }
    if (hd->nfd >= 0) {
        close(hd->nfd);
    }

    if (hd->bus) {
        sd_bus_unref(hd->bus);
        hd->bus = NULL;
    }
}


static const struct smp_operations sd_bluez_transport_ops = {
    .open = sd_bluez_fd_transport_connect,
    .read = sd_bluez_fd_transport_read,
    .write = sd_bluez_fd_transport_write,
    .close = sd_bluez_fd_transport_close,
    .get_mtu = sd_bluez_transport_get_mtu,
};


int sd_bluez_fd_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *bopts)
{
    int rc;

    if (!transport || !hd || !bopts) {
        return -EINVAL;
    }

    transport->ops = &sd_bluez_transport_ops;

    hd->nfd = -1;
    hd->wfd = -1;

    rc = sd_bluez_fill_dev_path(hd);
    if (rc) {
        DBG("PATH conv failed\n");
        return rc;
    }

    return 0;
}
