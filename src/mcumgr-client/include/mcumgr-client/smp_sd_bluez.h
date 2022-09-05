/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SMP_SD_BLUEZ_H
#define SMP_SD_BLUEZ_H

#include <systemd/sd-bus.h>

enum sd_bluez_method {
    SD_BLUEZ_METHOD_NONE = 0,
    SD_BLUEZ_METHOD_DBUS,
    SD_BLUEZ_METHOD_FD,
};


struct sd_bluez_opts {
    const char *mcumgr_char;
    int mtu;
    enum sd_bluez_method method;
};

struct smp_transport;

struct smp_sd_bluez_handle {
    struct sd_bluez_opts opts;
    char dev_path[40];
    int mtu;
    sd_bus *bus;
    uint8_t readbuf[512];
    size_t readoff;
    int read_rc;

    union {
        /* for char value based implementation */
        struct {
            sd_bus_slot *slot; /* notify handle */
            sd_event_source *timeout; /* timeout event handle */
        };
        /* fd based implementation */

        struct {
            int wfd; /* write fd */
            int nfd; /* notify fd */
        };
    };
};

int sd_bluez_transport_init(struct smp_transport *transport, struct smp_sd_bluez_handle *hd, struct sd_bluez_opts *sopts);
void print_sd_bluez_options(void);
int parse_sd_bluez_connstring(const char* connstring, struct sd_bluez_opts *ser_opts);

#endif
