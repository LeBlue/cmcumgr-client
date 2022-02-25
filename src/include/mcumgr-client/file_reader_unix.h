/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FILE_READER_UNIX_H
#define FILE_READER_UNIX_H

#include "file_reader.h"

struct file_unix_handle {
    const char *filename;
    size_t off;
    int fd;
};

int file_unix_init(struct file_reader *reader, struct file_unix_handle *fh, const char *filename);


#endif