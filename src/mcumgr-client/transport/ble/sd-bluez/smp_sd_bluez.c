/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <error.h>
#include <assert.h>

#include <systemd/sd-bus.h>

#include "sd_bluez.h"


int sd_bluez_check_smp_uuid(struct smp_sd_bluez_handle *hd, const char *path)
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

int sd_bluez_connect_device(struct smp_sd_bluez_handle *hd, const char *path)
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

int sd_bluez_transport_get_mtu(struct smp_transport *transport)
{
    struct smp_sd_bluez_handle *hd = sd_bluez_get_handle(transport);
    return hd->mtu - 3;
}


int sd_bluez_fd_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *bopts);
int sd_bluez_dbus_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *bopts);


int sd_bluez_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *bopts)
{
    if (!transport || !hd || !bopts) {
        return -EINVAL;
    }

    memset(transport, 0, sizeof(*transport));
    memset(hd, 0, sizeof(*hd));

    hd->opts = *bopts;
    transport->hd = (struct smp_handle*) hd;

    if (bopts->method == SD_BLUEZ_METHOD_FD) {
        return sd_bluez_fd_transport_init(transport, hd, bopts);
    } else if (bopts->method == SD_BLUEZ_METHOD_DBUS) {
        return sd_bluez_dbus_transport_init(transport, hd, bopts);
    }
    return -EINVAL;
}

int sd_bluez_fill_dev_path(struct smp_sd_bluez_handle *hd)
{
    int i = 0;
    char *tmp = hd->dev_path;
    strncpy(hd->dev_path, hd->opts.mcumgr_char, sizeof(hd->dev_path) - 1);

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

