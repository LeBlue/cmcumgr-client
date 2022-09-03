/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SMP_SERIAL_H
#define SMP_SERIAL_H

struct serial_opts {
    const char *port_name;
    int speed;
};

struct smp_transport;

struct smp_serial_handle {
    struct serial_opts opts;
    int port;
};

int serial_transport_init(struct smp_transport *transport, struct smp_serial_handle *hd, struct serial_opts *sopts);
void print_serial_options(void);
int parse_serial_connstring(const char* connstring, struct serial_opts *ser_opts);

#endif
