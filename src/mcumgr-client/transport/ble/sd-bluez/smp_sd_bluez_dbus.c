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
#include <sys/time.h>


#include <systemd/sd-bus.h>

#include "utils.h"

#include "mgmt_hdr.h"

#include "byteordering.h"

#include "sd_bluez.h"

#include <assert.h>


static int start_notify(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_error sderr = SD_BUS_ERROR_NULL;

    DBG("Call: %s %s %s %s\n", BLUEZ, path, IF_CHAR, "StartNotify");
    rc = sd_bus_call_method(hd->bus, BLUEZ, path, IF_CHAR, "StartNotify", &sderr, &msg, "");

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (sderr.message) {
            fprintf(stderr, "Failed to enable notification: %s\n", sderr.message);
        }
        sd_bus_message_unref(msg);
    } else {
        rc = 0;
    }
    return rc;
}

static int copy_property_value_msg(struct smp_sd_bluez_handle *hd, sd_bus_message *msg)
{
    int rc;
    size_t len = 0;
    const uint8_t *buf = NULL;

    /* enter variant as real type ay */
    rc = sd_bus_message_enter_container(msg, SD_BUS_TYPE_VARIANT, "ay");
    if (rc < 0) {
        DBG("Enter variant failed\n");
        return -EBADMSG;
    }

    /* read array */
    rc = sd_bus_message_read_array(msg, 'y', (const void**)&buf, &len);
    if (rc < 0) {
        return -EBADMSG;
    } else if (rc > 0) {
        if (len > (sizeof(hd->readbuf) - hd->readoff)) {
            return -ENOBUFS;
        }
        DBG("Read %d bytes\n", (int)len);
        memcpy(hd->readbuf + hd->readoff, buf, len);
        hd->readoff += len;
        rc = 0;
    }

    return rc;
}

static int properties_chaned_cb(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error)
{
    (void)ret_error;
    struct smp_sd_bluez_handle *hd = (struct smp_sd_bluez_handle *) userdata;
    const char *interface = NULL;
    int rc;

    DBG("Notify CB\n");

    // if (PRDBG) {
    //     sd_bus_message_dump(msg, stderr, SD_BUS_MESSAGE_DUMP_WITH_HEADER);
    //     sd_bus_message_rewind(msg, 1);
    // }

    rc = sd_bus_message_read(msg, "s", &interface);
    if (rc < 0) {
        assert(rc != -EINVAL);
        return 0;
    }

    DBG("Notify CB: %s\n", interface);

    /* ignore other interfaces */
    if (strcmp(interface, IF_CHAR)) {
        return 0;
    }

    /* iterate properties, only 'Value' is interesting */
    rc = sd_bus_message_enter_container(msg, SD_BUS_TYPE_ARRAY, "{sv}");
    if (rc < 0) {
        hd->read_rc = rc;
        return 0;
    }
    for (;;) {
        const char *key = NULL;
        char t;

        sd_bus_message_peek_type(msg, &t, NULL);
        DBG("Type: %c\n", t);
        if (t != SD_BUS_TYPE_DICT_ENTRY) {
            if (t == 0) {
                /* end of array reached */
                DBG("EOF\n");
                break;
            } else {
                DBG("Unexpected type: %d\n", t);
                hd->read_rc = -EBADMSG;
                return 0;
            }
        }

        /* enter dict entry */
        rc = sd_bus_message_enter_container(msg, SD_BUS_TYPE_DICT_ENTRY, "sv");
        if (rc < 0) {
            DBG("Enter dict Failed\n");
        }
        /* read property name (key of dict)*/
        rc = sd_bus_message_read(msg, "s", &key);
        if (rc < 0) {
            DBG("Read: 's' failed: %d\n", rc);
            hd->read_rc = rc;
            return 0;
        }
        if (rc == 0) {
            DBG("Read: 'a' finished\n");
            break;
        }
        DBG("Key: %s\n", key);

        /* ignore everything but 'Value' */
        if (strcmp(key, "Value")) {
            rc = sd_bus_message_skip(msg, "v");
            if (rc < 0) {
                DBG("SKIP 'v' failed\n");
            }
        } else {
            DBG("Read Value\n");
            rc = copy_property_value_msg(hd, msg);

            if (rc) {
                fprintf(stderr, "Decode and copy message failed: %d\n", rc);
                hd->read_rc = rc;
            } else {
                if (mgmt_header_is_rsp_complete(hd->readbuf, hd->readoff)) {
                    /* finished, exit event loop */
                    sd_event_exit(sd_bus_get_event(hd->bus), 0);
                }
            }
        }
        /* leave dict entry */
        rc = sd_bus_message_exit_container(msg);
        if (rc < 0) {
            DBG("Exit dict failed\n");
        }
    }

    /* leave root dict */
    sd_bus_message_exit_container(msg);
    /* ignore additional properties invalided: 'as', at end of message */


    /* on error, exit loop */
    if (rc < 0) {
        sd_event_exit(sd_bus_get_event(hd->bus), rc);
    }


    return 0;
}

static int stop_notify(struct smp_sd_bluez_handle *hd, const char *path)
{
    (void)path;
    if (hd->slot) {
        sd_bus_slot_unref(hd->slot);
        hd->slot = NULL;
    }

    return 0;
}

static int setup_notify(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;

    DBG("Add match: %s %s %s %s\n", BLUEZ, path, IF_PROPERTIES, "PropertiesChanged");
    if (hd->slot) {
        stop_notify(hd, path);
    }

    rc = sd_bus_match_signal(hd->bus, &hd->slot, BLUEZ, path, IF_PROPERTIES, "PropertiesChanged", properties_chaned_cb, hd);
    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        }
     } else {
        rc = 0;
    }

    return rc;
}


static int get_mtu(struct smp_sd_bluez_handle *hd, const char *path)
{
    uint16_t mtu;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    int rc;

    DBG("Get property: %s %s %s %s\n", BLUEZ, path, IF_CHAR, "MTU");
    rc = sd_bus_get_property_trivial(hd->bus, BLUEZ, path, IF_CHAR, "MTU", &err, 'q', &mtu);

    if (rc < 0) {
        /* also get -EINVAL if e.g interface does not exist on existing object. */
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to get MTU: %s\n", err.message);
        }
        return rc;
    } else {
        rc = 0;
        hd->mtu = mtu;
    }

    return rc;
}

static int sd_bluez_dbus_transport_connect(struct smp_transport *transport)
{
    if (!transport) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);
    if (!hd) {
        return -EINVAL;
    }

    int rc = 0;

    if (transport->verbose) {
        fprintf(stderr, "Using transport opts: %s\n", hd->opts.mcumgr_char);
    }

    rc = sd_bus_default_system(&hd->bus);
    if (rc < 0) {
        DBG("Connect system bus failed: %d\n", rc);
        return rc;
    }

    rc = sd_bluez_connect_device(hd, hd->dev_path);
    if (rc) {
        return rc;
    }

    rc = sd_bluez_check_smp_uuid(hd, hd->opts.mcumgr_char);
    if (rc) {
        return rc;
    }

    if (hd->opts.mtu) {
        hd->mtu = hd->opts.mtu;
    } else {
        rc = get_mtu(hd, hd->opts.mcumgr_char);
        if (rc) {
            return rc;
        }
    }

    rc = setup_notify(hd, hd->opts.mcumgr_char);
    if (rc) {
        return rc;
    }

    rc = start_notify(hd, hd->opts.mcumgr_char);
    if (rc) {
        stop_notify(hd, hd->opts.mcumgr_char);
        return rc;
    }

    /* TODO: flush pending dbus messages */

    return rc;
}


static int sd_bluez_dbus_transport_write(struct smp_transport *transport, uint8_t *buf, size_t len)
{
    DBG("Write transport: %p, buf: %p, len: %d\n", transport, buf, (int)len);

    if (!transport || !buf || !len) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);

    if (!hd) {
        return -EINVAL;
    }

    if (len > (size_t)sd_bluez_transport_get_mtu(transport)) {
        fprintf(stderr, "MTU %d too small\n", sd_bluez_transport_get_mtu(transport));
        return -E2BIG;
    }

    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_message *reply = NULL;

    sd_bus_error err = SD_BUS_ERROR_NULL;
    DBG("Call: %s %s %s %s\n", BLUEZ, hd->opts.mcumgr_char, IF_CHAR, "WriteValue");
    rc = sd_bus_message_new_method_call(hd->bus, &msg, BLUEZ, hd->opts.mcumgr_char, IF_CHAR, "WriteValue");

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to create write message: %s\n", err.message);
        }
     } else {
        rc = 0;
    }

    rc = sd_bus_message_append_array(msg, 'y', buf, len);
    if (rc < 0) {
        DBG("Failed append data to message: %d\n", rc);
        return rc;
    }

    rc = sd_bus_message_append(msg, "a{sv}", 0);
    if (rc < 0) {
        DBG("Failed to append empty options\n");
        return rc;
    }

    rc = sd_bus_call(hd->bus, msg, transport->timeout * 1000000, &err, &reply);
    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed write: %s\n", err.message);
        }
     } else {
        rc = 0;
    }
    sd_bus_message_unref(msg);
    sd_bus_message_unref(reply);

    return rc;
}


static int sd_bluez_dbus_transport_read(struct smp_transport *transport, uint8_t *buf, size_t maxlen)
{
    int rc = 0;

    DBG("Read\n");

    if (!transport || !buf || !maxlen) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);

    if (!hd) {
        return -EINVAL;
    }

    DBG("Read, args OK\n");

    int tmo = transport->timeout * 1000000;

    DBG("Read: tmo: %d, maxlen: %d\n", tmo, (int)maxlen);
    hd->readoff = 0;

    sd_event* loop = NULL;
    rc = sd_event_new(&loop);
    if (rc < 0) {
        fprintf(stderr, "Failed to setup event loop\n");
        return rc;
    }

    rc = sd_bus_attach_event(hd->bus, loop, 0);
    if (rc < 0) {
        DBG("Failed to add bus to loop\n");
        return rc;
    }

    /* add read timeout */
    sd_event_source *timeout = NULL;
    rc = sd_event_add_time_relative(loop, &timeout, CLOCK_MONOTONIC, tmo, 10000000, NULL, (void*) -ETIMEDOUT);
    if (rc < 0) {
        DBG("Failed to add timeout\n");
        hd->timeout = NULL;
        sd_event_unref(loop);
        return rc;
    }

    hd->timeout = timeout;

    /* do not close dbus connection on loop exit */
    sd_bus_set_close_on_exit(hd->bus, 0);

    /* wait for/process events until timeout, or event exits loop */
    rc = sd_event_loop(loop);

    /* cleanup event loop and timeout */
    sd_event_source_disable_unref(hd->timeout);
    hd->timeout = NULL;
    sd_bus_flush(hd->bus);
    sd_bus_detach_event(hd->bus);
    sd_event_unref(loop);

    if (rc == 0 || rc == -ETIMEDOUT) {
        /* on timeout, just copy what is available */
        int len = (hd->readoff < maxlen) ? hd->readoff : maxlen;
        memcpy(buf, hd->readbuf, len);
        rc = len;
    }

    return rc;
}

static void sd_bluez_dbus_transport_close(struct smp_transport *transport)
{
    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);

    stop_notify(hd, hd->opts.mcumgr_char);

    if (hd->bus) {
        sd_bus_flush_close_unref(hd->bus);
        hd->bus = NULL;
    }
}


static const struct smp_operations sd_bluez_transport_ops = {
    .open = sd_bluez_dbus_transport_connect,
    .read = sd_bluez_dbus_transport_read,
    .write = sd_bluez_dbus_transport_write,
    .close = sd_bluez_dbus_transport_close,
    .get_mtu = sd_bluez_transport_get_mtu,
};


int sd_bluez_dbus_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *bopts)
{
    int rc;

    if (!transport || !hd || !bopts) {
        return -EINVAL;
    }

    transport->ops = &sd_bluez_transport_ops;

    rc = sd_bluez_fill_dev_path(hd);
    if (rc) {
        DBG("PATH conv failed\n");
        return rc;
    }

    return 0;
}
