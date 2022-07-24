/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UTILS_TEST_H
#define UTILS_TEST_H

#include "ptest/ptest.h"
#include "utils.h"

#define _STR(x) #x
#define _XSTR(x) _STR(x)

#define PT_ASSERT_MEM_EQ(_mem1, _mem2, _len) \
do { \
    int _ret = memcmp(_mem1, _mem2, _len); \
    if (_ret != 0) { \
        hexdump(_mem1, _len, "\n" _XSTR(_mem1) "\n"); \
        hexdump(_mem2, _len,      _XSTR(_mem2) "\n"); \
        PT_ASSERT(0 == memcmp(_mem1, _mem2, _len)); \
    } \
} while (0)


#ifndef ASSERT_TEST_MSG
#define ASSERT_TEST_MSG(_expr, fmt, args...) \
    if (!(_expr)) { \
        fprintf(stderr, "\nTest setup failure: "  fmt "\n", ##args); \
    } \
    assert(_expr)

#endif

#endif

