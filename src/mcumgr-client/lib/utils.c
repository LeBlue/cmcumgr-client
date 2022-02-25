/*
 * Copyright (c) 2020-2021 Siddharth Chandrasekaran <sidcha.dev@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>

#include "include/utils.h"


void vfhexdump(FILE *stream, const void *p, size_t len, const char *fmt, va_list args)
{
	size_t i;
	char str[16 + 1] = { 0 };
	const uint8_t *data = p;

	vfprintf(stream, fmt, args);

	fprintf(stream, " [%zu] =>\n    0000  %02x ", len, data[0]);
	str[0] = isprint(data[0]) ? data[0] : '.';
	for (i = 1; i < len; i++) {
		if ((i & 0x0f) == 0) {
			fprintf(stream, " |%16s|", str);
			fprintf(stream, "\n    %04zu  ", i);
		} else if ((i & 0x07) == 0) {
			fprintf(stream, " ");
		}
		fprintf(stream, "%02x ", data[i]);
		str[i & 0x0f] = isprint(data[i]) ? data[i] : '.';
	}
	if ((i &= 0x0f) != 0) {
		if (i <= 8)
			fprintf(stream, " ");
		while (i < 16) {
			fprintf(stream, "   ");
			str[i++] = ' ';
		}
		fprintf(stream, " |%16s|", str);
	} else {
		fprintf(stream, " |%16s|", str);
	}

	fprintf(stream, "\n");
}

__attribute__((format(printf, 3, 4))) void hexdump(const void *p, size_t len, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfhexdump(stdout, p, len, fmt, args);
	va_end(args);
}

__attribute__((format(printf, 3, 4))) void ehexdump(const void *p, size_t len, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfhexdump(stderr, p, len, fmt, args);
	va_end(args);
}