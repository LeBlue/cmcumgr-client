/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <errno.h>

#include "ptest/ptest.h"
#include "utils_test.h"

#include "mcumgr-client/file_reader_unix.h"

/* must exist for the test with "Hello World!\n" content */
static const char *test_file_name = "file_reader_in.txt";

static void test_file_unix_init(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    int ret = file_unix_init(&reader, &fh, test_file_name);

    PT_ASSERT(ret == 0);
    PT_ASSERT(fh.filename != NULL);
    PT_ASSERT_STR_EQ(fh.filename, test_file_name);
    PT_ASSERT(reader.fh != NULL);
    PT_ASSERT(reader.op != NULL);
    PT_ASSERT(reader.op->read != NULL);
    PT_ASSERT(reader.op->open != NULL);
    PT_ASSERT(reader.op->close != NULL);
}

static void test_file_unix_init_fail_1(void)
{
    struct file_unix_handle fh;
    int ret = file_unix_init(NULL, &fh, test_file_name);

    PT_ASSERT(ret == -EINVAL);
}

static void test_file_unix_init_fail_2(void)
{
    struct file_reader reader;
    int ret = file_unix_init(&reader, NULL, test_file_name);

    PT_ASSERT(ret == -EINVAL);
}

static void test_file_unix_init_fail_3(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    int ret = file_unix_init(&reader, &fh, NULL);

    PT_ASSERT(ret == -EINVAL);
}


static void test_file_open(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    int ret = file_unix_init(&reader, &fh, test_file_name);

    PT_ASSERT(ret == 0);
    if (ret == 0) {
        ret = reader.op->open(reader.fh);
        PT_ASSERT(ret == 0);
        if (ret == 0) {
            reader.op->close(reader.fh);
        }
    }

}


static void test_file_open_fail_1(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    int ret = file_unix_init(&reader, &fh, test_file_name);

    PT_ASSERT(ret == 0);
    if (ret == 0) {
        ret = reader.op->open(NULL);
        PT_ASSERT(ret == -EINVAL);

        ret = reader.op->close(reader.fh);
        PT_ASSERT(ret == -EINVAL);

    }
}

static void test_file_open_fail_2(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    int ret = file_unix_init(&reader, &fh, "noexists.txt");

    PT_ASSERT(ret == 0);
    if (ret == 0) {
        ret = reader.op->open(NULL);
        PT_ASSERT(ret < 0); // should be -EPERM
    }
}



static void test_file_read(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    /* should contain "Hello World!\n" */
    int ret = file_unix_init(&reader, &fh, test_file_name);

    PT_ASSERT(ret == 0);
    if (ret == 0) {
        ret = reader.op->open(reader.fh);
        PT_ASSERT(ret == 0);
        if (ret == 0) {
            uint8_t buf[10];
            size_t sz = 10;
            ret = reader.op->read(reader.fh, buf, &sz, 0);
            PT_ASSERT(ret == 10);
            PT_ASSERT(buf[0] == 'H');
            PT_ASSERT_MEM_EQ(buf, "Hello Worl", 10);

            reader.op->close(reader.fh);
        }
    }
}

static void test_file_read_offset(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    /* should contain "Hello World!\n" */
    int ret = file_unix_init(&reader, &fh, test_file_name);

    PT_ASSERT(ret == 0);
    if (ret == 0) {
        ret = reader.op->open(reader.fh);
        PT_ASSERT(ret == 0);
        if (ret == 0) {
            uint8_t buf[10];
            size_t sz = 10;
            ret = reader.op->read(reader.fh, buf, &sz, 1);
            PT_ASSERT(ret == 10);
            PT_ASSERT(buf[0] == 'e');
            PT_ASSERT_MEM_EQ(buf, "ello World", 10);

            reader.op->close(reader.fh);
        }
    }
}


static void test_file_read_end(void)
{
    struct file_reader reader;
    struct file_unix_handle fh;
    /* should contain "Hello World!\n" */
    int ret = file_unix_init(&reader, &fh, test_file_name);

    PT_ASSERT(ret == 0);
    if (ret == 0) {
        ret = reader.op->open(reader.fh);
        PT_ASSERT(ret == 0);
        if (ret == 0) {
            uint8_t buf[10];
            size_t sz = 10;
            ret = reader.op->read(reader.fh, buf, &sz, 6);
            PT_ASSERT(ret == 7);
            PT_ASSERT(buf[0] == 'W');
            PT_ASSERT_MEM_EQ(buf, "World!\n", 7);

            reader.op->close(reader.fh);
        }
    }
}


static void suite_file_reader(void)
{
    pt_add_test(test_file_unix_init, "Test reading file: init: OK", "Suite file reader");
    pt_add_test(test_file_unix_init_fail_1, "Test reading file: init: fail 1", "Suite file reader");
    pt_add_test(test_file_unix_init_fail_2, "Test reading file: init: fail 2", "Suite file reader");
    pt_add_test(test_file_unix_init_fail_3, "Test reading file: init: fail 3", "Suite file reader");

    pt_add_test(test_file_open, "Test reading file: open: OK", "Suite file reader");
    pt_add_test(test_file_open_fail_1, "Test reading file: open: fail 1", "Suite file reader");
    pt_add_test(test_file_open_fail_2, "Test reading file: open: fail 2", "Suite file reader");

    pt_add_test(test_file_read, "Test reading file: read at 0: OK", "Suite file reader");
    pt_add_test(test_file_read_offset, "Test reading file: read at 1: OK", "Suite file reader");
    pt_add_test(test_file_read_end, "Test reading file: read at 6 till end: OK", "Suite file reader");

}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pt_add_suite(suite_file_reader);

    return pt_run();
}
