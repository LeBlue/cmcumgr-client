/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TRANSPORT_SD_BLUEZ_H
#define TRANSPORT_SD_BLUEZ_H

#define BLUEZ "org.bluez"


#define IF_ADAPTER "org.bluez.Adapter1"
#define IF_DEVICE "org.bluez.Device1"
#define IF_SERVICE "org.bluez.GattService1"
#define IF_CHAR "org.bluez.GattCharacteristic1"

#define IF_PROPERTIES "org.freedesktop.DBus.Properties"
#define IF_OBJ_MANAGER "org.freedesktop.DBus.ObjectManager"

#include "../smp_ble.h"
#include "smp_sd_bluez.h"
#include "smp_transport.h"

#define PRDBG 0
#if PRDBG
#include <stdio.h>
#define DBG(fmt, args...) do { fprintf(stderr, "dbg: smp_sd_bluez: " fmt, ##args); } while (0)
#else
#define DBG(fmt, args...) do {} while (0)
#endif

static inline struct smp_sd_bluez_handle *sd_bluez_get_handle(struct smp_transport *transport)
{
    struct smp_sd_bluez_handle *hd = (struct smp_sd_bluez_handle *) transport->hd;
    return hd;
}


int sd_bluez_check_smp_uuid(struct smp_sd_bluez_handle *hd, const char *path);
int sd_bluez_connect_device(struct smp_sd_bluez_handle *hd, const char *path);
int sd_bluez_fill_dev_path(struct smp_sd_bluez_handle *hd);
int sd_bluez_transport_get_mtu(struct smp_transport *transport);

#endif
