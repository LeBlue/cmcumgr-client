/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "mcumgr-client/file_reader_unix.h"


static int file_open_impl(struct file_handle* fh)
{
    struct file_unix_handle *fuh = (struct file_unix_handle *) fh;

    if (!fuh || !fuh->filename) {
        return -EINVAL;
    }

    fuh->off = 0;
    fuh->fd = open(fuh->filename, O_RDONLY);

    if (fuh->fd < 0) {
        return -errno;
    }

    return 0;
}

static int file_read_impl(struct file_handle* fh, uint8_t *buf, size_t *sz, size_t off)
{
    ssize_t ret;
    size_t bytes_read = 0;
    struct file_unix_handle *fuh = (struct file_unix_handle *) fh;


    if (!fuh || fuh->fd < 0 || !buf || !sz || !*sz) {
        return -EINVAL;
    }

    if (off != fuh->off) {
        off_t soff = lseek(fuh->fd, off, SEEK_SET);
        if (((off_t)-1) == soff) {
            return -errno;
        }
        fuh->off = soff;
    }
    while ((ret = read(fuh->fd, buf + bytes_read, *sz - bytes_read)) > 0) {
        bytes_read += ret;
        if (bytes_read >= *sz) {
            break;
        }
    }

    if (ret < 0) {
        return -errno;
    }

    *sz -= bytes_read;

    return bytes_read;
}

static int file_close_impl(struct file_handle *fh)
{
    struct file_unix_handle *fuh = (struct file_unix_handle *) fh;

    if (!fh || fuh->fd < 0) {
        return -EINVAL;
    }
    close(fuh->fd);
    fuh->fd = -1;
    return 0;
}


static const struct file_operations file_op = {
    .open = file_open_impl,
    .read = file_read_impl,
    .close = file_close_impl
};

int file_unix_init(struct file_reader *reader, struct file_unix_handle *fh, const char *filename)
{
    if (!reader || !fh || !filename) {
        return -EINVAL;
    }

    reader->op = &file_op;

    fh->filename = filename;
    fh->fd = -1;
    fh->off = 0;
    reader->fh = (struct file_handle *) fh;

    return 0;
}
