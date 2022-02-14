/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>

#include "serial_port.h"
#include "utils.h"

#ifdef __linux__
#include <libgen.h>

static char *devname;

static void
port_open_storename(const char *name)
{
    devname = strdup(name);
    if (!devname) {
        return;
    }
    devname = basename(devname);
}

static void port_setup_lowlatency(const char *string)
{
    int fd;
    char filename[128];

    snprintf(filename, sizeof(filename) - 1,
             "/sys/bus/usb-serial/devices/%s/latency_timer", devname);
    fd = open(filename, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Warning: failed to set %s to %s: %s\n",
                filename, string, strerror(errno));
        return;
    }
    write(fd, string, strlen(string));
    close(fd);
}
#endif

int port_open(const char *name)
{
    int fd;

    fd = open(name, O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        fd = -errno;
        fprintf(stderr, "port %s open failed\n", name);
    }
#ifdef __linux__
    port_open_storename(name);
#endif
    return fd;
}

int port_setup(int fd, unsigned long speed)
{
    struct termios tios;
    int rc;

    rc = tcgetattr(fd, &tios);
    if (rc < 0) {
        rc = -errno;
        fprintf(stderr, "tcgetattr() fail: %s\n", strerror(errno));
        return rc;
    }

    tios.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUTF8
    tios.c_iflag &= ~IUTF8;
#endif
    tios.c_oflag &= ~(OPOST | OCRNL | TABDLY);
#ifdef OFILL
    tios.c_oflag &= ~OFILL;
#endif
#ifdef OFDEL
    tios.c_oflag &= ~OFDEL;
#endif
#ifdef NLDLY
    tios.c_oflag &= ~(NLDLY | CRDLY | BSDLY | FFDLY  | VTDLY);
#endif
    tios.c_oflag |= ONOCR | ONLRET;
    tios.c_cflag &= ~(CSIZE | CSTOPB | CRTSCTS);
    tios.c_cflag |= CS8 | CREAD | CLOCAL;
    tios.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK |
      ECHONL | ECHOCTL | ECHOPRT | ECHOKE | FLUSHO | NOFLSH |
      TOSTOP | PENDIN | IEXTEN);

    switch (speed) {
#ifdef B115200
    case 115200:
        speed = B115200;
        break;
#endif
#ifdef B230400
    case 230400:
        speed = B230400;
        break;
#endif
#ifdef B921600
    case 921600:
        speed = B921600;
        break;
#endif
#ifdef B1000000
    case 1000000:
        speed = B1000000;
        break;
#endif
    default:
        fprintf(stderr, "Invalid speed %ld for this platform\n", speed);
        return -EINVAL;
    }
    rc = cfsetspeed(&tios, (speed_t)speed);
    if (rc < 0) {
        rc = -errno;
        fprintf(stderr, "cfsetspeed(%lu) fail: %s\n", speed,
                strerror(errno));
        return rc;
    }

    rc = tcsetattr(fd, TCSANOW, &tios);
    if (rc < 0) {
        fprintf(stderr, "tcsetattr() fail: %s\n", strerror(errno));
        return rc;
    }
#ifdef __linux__
    if (0)
        port_setup_lowlatency("1");
#endif
    return 0;
}

int port_write_data(int fd, const void *buf, size_t len)
{
    if (write(fd, buf, len) != (ssize_t)len) {
        int err = -errno;
        fprintf(stderr, "Write failed: %s\n", strerror(errno));
        return err;
    }
    return 0;
}

int port_read_poll(int fd, char *buf, size_t maxlen, int end_time, int verbose)
{
    int now;
    int rc = 0;

    while (!rc) {
        now = time_get();
        if (now > end_time) {
            fprintf(stderr, "Read timed out\n");
            return -ETIMEDOUT;
        }
        rc = read(fd, buf, maxlen);
        if (rc < 0 && (errno == EAGAIN || ((EAGAIN != EWOULDBLOCK) && errno == EWOULDBLOCK))) {
            rc = 0;
        }
        if (rc > 0 && verbose > 1) {
            ehexdump(buf, rc, "RX");
        }
    }
    if (rc < 0) {
        rc = -errno;
        fprintf(stderr, "Read failed: %d %s\n", errno, strerror(errno));
    }
    return rc;
}

int time_get(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return tv.tv_sec;
}
