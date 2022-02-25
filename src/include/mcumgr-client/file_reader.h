/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FILE_READER_H
#define FILE_READER_H

#include <stdint.h>
#include <stddef.h>

struct file_handle;

typedef int (*file_open_fn)(struct file_handle* fh);
typedef int (*file_close_fn)(struct file_handle* fh);
typedef int (*file_read_fn)(struct file_handle* fh, uint8_t *buf, size_t *sz, size_t off);

struct file_operations {
    file_open_fn open;
    file_close_fn close;
    file_read_fn read;
};

struct file_reader {
    struct file_handle *fh;
    const struct file_operations *op;
};

#endif