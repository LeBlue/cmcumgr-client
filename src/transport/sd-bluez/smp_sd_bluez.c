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
static const char IF_PROPERTIES[] = "org.freedesktop.DBus.Properties";

#include <assert.h>

static inline struct smp_sd_bluez_handle *get_handle(struct smp_transport *transport)
{
    struct smp_sd_bluez_handle *hd = (struct smp_sd_bluez_handle *) transport->hd;
    return hd;
}

static int start_notify(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    DBG("Call: %s %s %s %s\n", BLUEZ, path, IF_CHAR, "StartNotify");
    rc = sd_bus_call_method(hd->bus, BLUEZ, path, IF_CHAR, "StartNotify", &err, &msg, "");

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to enable notification: %s\n", err.message);
        }
        sd_bus_message_unref(msg);
    } else {
        rc = 0;
    }
    return rc;
}

// static int message_read_byte_array(sd_bus_message *msg, uint8_t *buf, size_t sz)
// {
//     int rc;
//     size_t off;

//     /* iterate through value bytes array */
//     rc = sd_bus_message_enter_container(msg, 'a', "y");
//     if (rc < 0) {
//         return rc;
//     }

//     for (off = 0; off < sz; off++) {
//         const uint8_t byte;

//         rc = sd_bus_message_read(msg, "y", &byte);
//         if (rc < 0) {
//             DBG("Read: 's' failed: %d\n", rc);
//             return rc;
//         }
//         if (rc == 0) {
//             DBG("Read: 'a' finished\n");
//             break;
//         }
//         buf[off] = byte;
//     }
//     /* no buf space, skip over, TODO: return err? */
//     if (rc > 0) {
//         while (sd_bus_message_skip(msg, "y") == 0) {
//         }
//     }

//     rc = sd_bus_message_exit_container(msg);

//     return off;
// }

// static int copy_property_value_msg(struct smp_sd_bluez_handle *hd, sd_bus_message *msg)
// {
//     int rc;
//     char *signature = NULL;

//     /* enter variant as real type ay */
//     rc = sd_bus_message_read(msg, "v", "g", &signature);
//     if (rc < 0) {
//         DBG("Failed read 'Value' container variant: %d\n", rc);
//         hd->read_rc = rc;
//         return 0;
//     }
//     DBG("Signature: '%s'\n", signature);
//     free(signature);

//     if ((sizeof(hd->readbuf) - hd->readoff) > 0) {
//         // TODO: convert to use sd_bus_message_read_array()
//         rc =  message_read_byte_array(msg, hd->readbuf + hd->readoff, sizeof(hd->readbuf) - hd->readoff);
//         if (rc > 0) {
//             hd->readoff += rc;
//             rc = 0;
//         }
//     } else {
//         fprintf(stderr, "Notify: no buf space\n");
//         hd->read_rc = -ENOBUFS;
//     }
//     return rc;
// }

// static int message_read_byte_array(sd_bus_message *msg, uint8_t *buf, size_t sz)
// {
//     int rc;
//     size_t off;

//     /* iterate through value bytes array */
//     rc = sd_bus_message_enter_container(msg, 'a', "y");
//     if (rc < 0) {
//         return rc;
//     }

//     for (off = 0; off < sz; off++) {
//         const uint8_t byte;

//         rc = sd_bus_message_read(msg, "y", &byte);
//         if (rc < 0) {
//             DBG("Read: 's' failed: %d\n", rc);
//             return rc;
//         }
//         if (rc == 0) {
//             DBG("Read: 'a' finished\n");
//             break;
//         }
//         buf[off] = byte;
//     }
//     /* no buf space, skip over, TODO: return err? */
//     if (rc > 0) {
//         while (sd_bus_message_skip(msg, "y") == 0) {
//         }
//     }

//     rc = sd_bus_message_exit_container(msg);

//     return off;
// }

static int copy_property_value_msg(struct smp_sd_bluez_handle *hd, sd_bus_message *msg)
{
    int rc;
    char *signature = NULL;

    /* enter variant as real type ay */
    rc = sd_bus_message_enter_container(msg, SD_BUS_TYPE_VARIANT, "ay");
    if (rc < 0) {
        DBG("Enter variant failed\n");
        return -EBADMSG;
    }
    /* read array */
    size_t len = 0;
    const uint8_t *buf = NULL;
    // const void *bufp = (void*) buf;
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

static int notify_cb(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error)
{
    struct smp_sd_bluez_handle *hd = (struct smp_sd_bluez_handle *) userdata;
    (void)ret_error;

    DBG("Notify CB\n");
    const char *interface = NULL;
    int rc;

    sd_bus_message_dump(msg, stderr, SD_BUS_MESSAGE_DUMP_WITH_HEADER);
    sd_bus_message_rewind(msg, 1);

    rc = sd_bus_message_read(msg, "s", &interface);
    if (rc < 0) {
        assert(rc != -EINVAL);
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
        /* read Property name (key of dict)*/
        rc = sd_bus_message_read(msg, "s", &key);
        if (rc < 0) {
            DBG("Read: 's' failed: %d\n", rc);
            hd->read_rc = rc;
            return 0;
        }
        if (rc == 0) {
            DBG("Read: 'a' finised\n");
            break;
        }
        DBG("Key: %s\n", key);
        if (strcmp(key, "Value")) {
            DBG("Skip %s\n", key);
            rc = sd_bus_message_skip(msg, "v");
            if (rc < 0) {
                DBG("SKIP 'v' failed\n");
            }
            // rc = sd_bus_message_exit_container(msg);
            // if (rc < 0) {
            //     DBG("Exit dict failed\n");
            // }
            // continue;
        } else {
            DBG("Read Value\n");
            // TODO: sd_bus_message_read_array

            rc = copy_property_value_msg(hd, msg);
            if (rc) {
                fprintf(stderr, "Decode and copy message failed: %d\n", rc);
                hd->read_rc = rc;
            } else {
                if (mgmt_header_is_rsp_complete(hd->readbuf, hd->readoff)) {
                    sd_event *loop = NULL;
                    sd_event_default(&loop);
                    sd_event_exit(loop, 0);
                }
            }
        }
        /* leave dict entry */
        rc = sd_bus_message_exit_container(msg);
        if (rc < 0) {
            DBG("Exit dict failed\n");
        }
    }

    if (rc < 0) {
        sd_event *loop = NULL;
        sd_event_default(&loop);
        sd_event_exit(loop, rc);
        // sd_event_unref(loop);
    }

    /* leave root dict */
    rc = sd_bus_message_exit_container(msg);

    /* ignore additional properties invalided: 'as', at end of message */

    return 0;
}


static int setup_notify(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;

    DBG("Add match: %s %s %s %s\n", BLUEZ, path, IF_PROPERTIES, "PropertiesChanged");
    if (hd->slot) {
        sd_bus_slot_unref(hd->slot);
    }

    rc = sd_bus_match_signal(hd->bus, &hd->slot, BLUEZ, path, IF_PROPERTIES, "PropertiesChanged", notify_cb, hd);
    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        }
     } else {
        rc = 0;
    }

    return rc;
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

static int connect_device(struct smp_sd_bluez_handle *hd, const char *path)
{
    int rc;
    sd_bus_message *msg = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    DBG("Call: %s %s %s %s\n", BLUEZ, path, IF_DEVICE, "Connect");
    rc = sd_bus_call_method(hd->bus, BLUEZ,path, IF_DEVICE, "Connect", &err, &msg, "");

    if (rc < 0) {
        if (rc == -EINVAL) {
            assert(rc != -EINVAL);
        } else if (err.message) {
            fprintf(stderr, "Failed to connect: %s", err.message);
        }
     } else {
        rc = 0;
    }

    sd_bus_message_unref(msg);
    return rc;
}


static int check_smp_uuid(struct smp_sd_bluez_handle *hd, const char *path)
{
    char *uuid = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    int rc;

    DBG("Get property: %s %s %s %s\n", BLUEZ, path, IF_CHAR, "UUID");
    rc = sd_bus_get_property_string(hd->bus, BLUEZ, path, IF_CHAR, "UUID", &err, &uuid);

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
        rc = -EINVAL;
    }
    if (uuid) {
        free(uuid);
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
            fprintf(stderr, "Failed to get MTU: %s", err.message);
        }
        return rc;
    } else {
        rc = 0;
        hd->mtu = mtu;
    }

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

    rc = connect_device(hd, hd->dev_path);
    if (rc) {
        return rc;
    }

    rc = check_smp_uuid(hd, hd->opts.mcumgr_char);
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

    if (!hd) {
        return -EINVAL;
    }

    DBG("Write 2\n");

    // if (len > (hd->mtu - 3) ) {
    //     return -E2BIG;
    // }

    /* Todo: check write length with MTU */
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
            fprintf(stderr, "Failed to create write message: %s", err.message);
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
            fprintf(stderr, "Failed write: %s", err.message);
        }
     } else {
        rc = 0;
    }
    sd_bus_message_unref(msg);
    sd_bus_message_unref(reply);

    return rc;
}


// static int time_now(void)
// {
//     struct timeval tv;

//     gettimeofday(&tv, NULL);

//     return tv.tv_sec;
// }


static int sd_bluez_transport_read(struct smp_transport *transport, uint8_t *buf, size_t maxlen)
{
    int rc = 0;

    DBG("Read\n");

    if (!transport || !buf || !maxlen) {
        return -EINVAL;
    }

    struct smp_sd_bluez_handle *hd = get_handle(transport);

    if (!hd) {
        return -EINVAL;
    }

    DBG("Read, args OK\n");

    int tmo = transport->timeout * 1000000;

    DBG("Read: tmo: %d, maxlen: %d\n", tmo, (int)maxlen);

    // int now = time_now();

    sd_event* loop = NULL;
    rc = sd_event_default(&loop);

    if (rc < 0) {
        DBG("Failed to init loop\n");
        return rc;
    }
    sd_event_source *timeout = NULL;
    rc = sd_event_add_time_relative(loop, &timeout, CLOCK_MONOTONIC, tmo, 10000000, NULL, (void*) -ETIMEDOUT);
    if (rc < 0) {
        DBG("Failed to add timeout\n");
        sd_event_unref(loop);
        return rc;
    }

    rc = sd_bus_attach_event(hd->bus, loop, 0);
    if (rc < 0) {
        DBG("Failed to add bus to loop\n");
        return rc;
    }

    rc = sd_event_loop(loop);

    if (rc == 0 || rc == -ETIMEDOUT) {
        /* on timeout, just copy what is available */
        int len = (hd->readoff < maxlen) ? hd->readoff : maxlen;
        memcpy(buf, hd->readbuf, len);
        rc = len;
    }

    sd_bus_detach_event(hd->bus);
    sd_event_unref(loop);
    return rc;
}

void sd_bluez_transport_close(struct smp_transport *transport)
{
    struct smp_sd_bluez_handle *hd = get_handle(transport);

    stop_notify(hd, hd->opts.mcumgr_char);

    /* todo: move, as not symmetric with open, but with init */
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


static int dev_path_from_char_path(struct smp_sd_bluez_handle *hd, const char *mcumgr_path)
{
    int i = 0;
    char *tmp = hd->dev_path;

    strncpy(hd->dev_path, mcumgr_path, sizeof(hd->dev_path) - 1);

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
    return 0;
}

int sd_bluez_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *bopts)
{
    int rc;

    if (!transport || !hd || !bopts) {
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    memset(hd, 0, sizeof(*hd));

    transport->ops = &sd_bluez_transport_ops;
    transport->hd = (struct smp_handle*) hd;

    hd->opts = *bopts;

    rc = dev_path_from_char_path(hd, bopts->mcumgr_char);
    if (rc) {
        DBG("PATH conv failed\n");
        return rc;
    }

    rc = sd_bus_default_system(&hd->bus);
    if (rc < 0) {
        DBG("Get bus failed: %d\n", rc);
        return rc;
    }

    return 0;
}
