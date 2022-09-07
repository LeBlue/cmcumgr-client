/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>


#include "ptest.h"

static const char *prgpath = NULL;

void pt_set_prgpath(const char *argv0)
{
	if (!prgpath) {
		char *path = strdup(argv0);
		PT_ASSERT_TEST_SETUP(path != NULL, "Malloc failed");
		prgpath = dirname(path);
	}
}

char *pt_get_file_path(const char *filename)
{
	char *fpath;

	PT_ASSERT_TEST_SETUP(prgpath, "Program path not set");

	fpath = malloc(strlen(prgpath) + 1 + strlen(filename) + 1);
	PT_ASSERT_TEST_SETUP(fpath, "malloc failed");

	sprintf(fpath, "%s/%s", prgpath, filename);

	/* try opening, should be there */
	FILE *f = fopen(fpath, "r");
	if (f == NULL) {
		PT_ASSERT_TEST_SETUP(f != NULL, "Test file %s not found", fpath);
	}

	fclose(f);
	return fpath;
}
