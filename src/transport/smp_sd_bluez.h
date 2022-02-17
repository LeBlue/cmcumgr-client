/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SMP_SD_BLUEZ_H
#define SMP_SD_BLUEZ_H

#include <systemd/sd-bus.h>

struct sd_bluez_opts {
    const char *mcumgr_char;
    int mtu;
};

struct smp_transport;

struct smp_sd_bluez_handle {
    struct sd_bluez_opts opts;
    char dev_path[40];
    int mtu;
    sd_bus *bus;
    sd_bus_slot *slot; /* notify handle */
    uint8_t readbuf[512];
    size_t readoff;
    int read_rc;
};

int sd_bluez_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *sopts);

int parse_sd_bluez_connstring(const char* connstring, struct sd_bluez_opts *ser_opts);

#endif