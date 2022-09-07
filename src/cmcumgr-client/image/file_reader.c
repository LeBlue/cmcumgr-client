/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include "file_reader.h"

int file_reader_open(struct file_reader *fr)
{
	if (!fr || !fr->op || !fr->op->open) {
		return -EINVAL;
	}
	return fr->op->open(fr->fh);
}

int file_reader_close(struct file_reader *fr)
{
	if (!fr || !fr->op || !fr->op->close) {
		return -EINVAL;
	}
	return fr->op->close(fr->fh);

}

int file_reader_read(struct file_reader *fr, uint8_t *buf, size_t *sz, size_t off)
{
	if (!fr || !fr->op || !fr->op->read) {
		return -EINVAL;
	}
	return fr->op->read(fr->fh, buf, sz, off);
}

int file_reader_is_valid(struct file_reader *fr)
{
	if (!fr || !fr->op || !fr->fh) {
		return 0;
	}

	return 1;
}
