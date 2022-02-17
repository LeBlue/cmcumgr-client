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

#include "smp_transport.h"
#include "smp_sd_bluez.h"

#define PRDBG 1
#if PRDBG
#include <stdio.h>
#define DBG(fmt, args...) do { fprintf(stderr, "dbg: smp_sd_bluez: " fmt, ##args); } while (0)
#else
#define DBG(fmt, args...) do {} while (0)
#endif

#define SMP_BLUETOOTH_UUID "da2e7828-fbce-4e01-ae9e-261174997c48"

// static const char BLUEZ[] = "org.bluez";
#define BLUEZ "org.bluez"
static const char IF_ADAPTER[] = "org.bluez.Adapter1";
// static const char IF_DEVICE[] = "org.bluez.Device1";
#define IF_DEVICE "org.bluez.Device1"
static const char IF_CHAR[] = "org.bluez.GattCharacteristic1";

#include <assert.h>

static inline struct smp_sd_bluez_handle *get_handle(struct smp_transport *transport)
{
    struct smp_sd_bluez_handle *hd = (struct smp_sd_bluez_handle *) transport->hd;
    return hd;
}


int get_notify_fd(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    uint16_t mtu;
    int fd;

    DBG("Call: %s %s %s %s\n", BLUEZ, path, IF_CHAR, "AcquireNotify");
    rc = sd_bus_call_method(hd->bus, BLUEZ, path, IF_CHAR, "AcquireNotify", &err, &msg, "a{sv}", 0, NULL);

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to connect: %s\n", err.message);
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
        hd->mtu = mtu;
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

int get_write_fd(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    uint16_t mtu;
    int fd;

    DBG("Call: %s %s %s %s\n", BLUEZ, hd->opts.mcumgr_char, IF_CHAR, "AcquireWrite");
    rc = sd_bus_call_method(hd->bus, BLUEZ, hd->opts.mcumgr_char, IF_CHAR, "AcquireWrite", &err, &msg, "a{sv}", 0, NULL);

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to connect: %s\n", err.message);
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

int sd_bluez_transport_connect(struct smp_transport *transport)
{
    if (!transport) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = get_handle(transport);
    if (!hd) {
        return -EINVAL;
    }

    struct sd_bluez_opts *sopts = &hd->opts;
    int rc = 0;

    if (transport->verbose) {
        fprintf(stderr, "Using transport opts: %s\n", sopts->mcumgr_char);
    }

    sd_bus_message *msg = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    DBG("Call: %s %s %s %s\n", BLUEZ, hd->opts.mcumgr_char, IF_DEVICE, "Connect");
    rc = sd_bus_call_method(hd->bus, BLUEZ, hd->dev_path, IF_DEVICE, "Connect", &err, &msg, "");

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to connect: %s", err.message);
        }
        sd_bus_message_unref(msg);
        return rc;
    } else {
        rc = 0;
    }

    err = SD_BUS_ERROR_NULL;
    sd_bus_message_unref(msg);
    msg = NULL;
    char *uuid = NULL;

    sd_bus_error errp = SD_BUS_ERROR_NULL;
    DBG("Get property: %s %s %s %s\n", BLUEZ, hd->opts.mcumgr_char, IF_CHAR, "UUID");
    rc = sd_bus_get_property_string(hd->bus, BLUEZ, hd->opts.mcumgr_char, IF_CHAR, "UUID", &errp, &uuid);

    if (rc < 0) {
        /* also get -EINVAL if e.g interface does not exist on existing object. */
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to check mcumgr characteristic UUID: %s", err.message);
        }
        return rc;
    } else {
        rc = 0;
    }
    if (0 != (strcmp(uuid, SMP_BLUETOOTH_UUID))) {
        fprintf(stderr, "Wrong characteristic with uuid %s\n", uuid);
        free(uuid);
        return -EINVAL;
    }
    free(uuid);

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

int sd_bluez_transport_write(struct smp_transport *transport, uint8_t *buf, size_t len)
{
    DBG("Write\n");

    DBG("transport: %p, buf: %p, len: %d\n", transport, buf, (int)len);

    if (!transport || !buf || !len) {
        return -EINVAL;
    }


    struct smp_sd_bluez_handle *hd = get_handle(transport);

    DBG("hd: %p, wfd: %d\n", hd, hd->wfd ? hd->wfd : -2);

    if (!hd || hd->wfd < 0) {
        return -EINVAL;
    }

    DBG("Write 2\n");

    if (len > (hd->mtu - 3) ) {
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


static int sd_bluez_transport_read(struct smp_transport *transport, uint8_t *buf, size_t maxlen)
{
    int rc = 0;
    size_t readlen = maxlen;
    uint8_t *readbuf = buf;

    DBG("Read\n");

    if (!transport || !buf || !maxlen) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = get_handle(transport);

    if (!hd || hd->nfd < 0) {
        return -EINVAL;
    }

    DBG("Read, args OK\n");

    int tmo = transport->timeout;

    DBG("Read: tmo: %d, maxlen: %d\n", tmo, (int)readlen);

    int now = time_now();
    int end_time = now + tmo + 2;

    while (readlen > 0) {

        now = time_now();
        if (now > end_time) {
            fprintf(stderr, "Read timed out\n");
            return -ETIMEDOUT;
        }

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
                // break;
            }
            DBG("Read, %d\n", (int) (maxlen - readlen));
        } else {
            printf("Read 0\n");
            return -ETIMEDOUT;
        }

    }

    DBG("Read, %d\n", (int) (maxlen - readlen));


    return rc;
}

void sd_bluez_transport_close(struct smp_transport *transport)
{
    struct smp_sd_bluez_handle *hd = get_handle(transport);
    int rc = 0;

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
    .open = sd_bluez_transport_connect,
    .read = sd_bluez_transport_read,
    .write = sd_bluez_transport_write,
    .close = sd_bluez_transport_close,
};


int sd_bluez_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *bopts)
{
    if (!transport || !hd || !bopts) {
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    memset(hd, 0, sizeof(*hd));

    transport->ops = &sd_bluez_transport_ops;
    transport->hd = (struct smp_handle*) hd;

    hd->opts = *bopts;
    hd->nfd = -1;
    hd->wfd = -1;
    strncpy(hd->dev_path, bopts->mcumgr_char, sizeof(hd->dev_path) - 1);
    int i = 0;
    char *tmp = hd->dev_path;
    for (; *tmp != '\0'; ++tmp) {
        if (*tmp == '/') {
            ++i;
            if (i == 5) {
                *tmp = '\0';
                break;
            }
        }
    }
    if (i < 4) {
        return -EINVAL;
    }

    int ret = sd_bus_default_system(&hd->bus);
    if (!ret) {
        return ret;
    }

    return 0;
}
