/*
Work is Licensed under BSD3

Copyright (c) 2013, Daniel Holden, All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this
   list of conditions and the following disclaimer in the documentation and/or
   other materials provided with the distribution.
3. Neither the name of the ptest nor the names of its contributors may be used to
   endorse or promote products derived from this software without specific prior
   written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef ptest_h
#define ptest_h

#include <string.h>

#define _STR(x) #x
#define _XSTR(x) _STR(x)

#define PT_SUITE(name) void name(void)

#define PT_FUNC(name) static void name(void)
#define PT_REG(name) pt_add_test(name, #name, __func__)
#define PT_TEST(name) auto void name(void); PT_REG(name); void name(void)

#define PT_ASSERT(expr) pt_assert_run((int)(expr), #expr, __func__, __FILE__, __LINE__)
#define PT_ASSERT_STR_EQ(fst, snd) pt_assert_run(strcmp(fst, snd) == 0, "strcmp( " #fst ", " #snd " ) == 0", __func__, __FILE__, __LINE__)

__attribute__((format(printf, 3, 4))) void pt_hexdump(const void *p, size_t len, const char *fmt, ...);

#define PT_ASSERT_MEM_EQ(_mem1, _mem2, _len)                                                                           \
	do {                                                                                                           \
		int _ret = memcmp(_mem1, _mem2, _len);                                                                 \
		if (_ret != 0) {                                                                                       \
			pt_hexdump(_mem1, _len, "\n" _XSTR(_mem1) "\n");                                               \
			pt_hexdump(_mem2, _len, _XSTR(_mem2) "\n");                                                    \
		}                                                                                                      \
		PT_ASSERT(_ret == 0);                                                                                  \
	} while (0)

#define PT_ASSERT_TEST_SETUP(_expr, fmt, ...)                                                                          \
	if (!(_expr)) {                                                                                                \
		fprintf(stderr, "\nTest setup failure: " fmt "\n", ##__VA_ARGS__);                                     \
	}                                                                                                              \
	assert(_expr)

#define _PT_NAME_TEST_MAX 100
#define PT_TEST_ADD_WITH_PARAMETERS_NAME(_func, _params, _suite, _name, _fmt, _field)                                  \
	do {                                                                                                           \
		char _t_namebuf[_PT_NAME_TEST_MAX];                                                                    \
		_t_namebuf[_PT_NAME_TEST_MAX - 1] = '\0';                                                              \
		for (unsigned int _pidx = 0; _pidx < (sizeof(_params) / sizeof(_params[0])); ++_pidx) {                \
			snprintf(_t_namebuf, sizeof(_t_namebuf) - 1, "%s: " _fmt, _name, _params[_pidx]._field);       \
			pt_add_test_w_param(_func, &_params[_pidx], _t_namebuf, _suite);                               \
		}                                                                                                      \
	} while (0)

#define PT_TEST_ADD_WITH_PARAMETERS(_func, _params, _suite, _name)                                                     \
	do {                                                                                                           \
		char _t_namebuf[_PT_NAME_TEST_MAX];                                                                    \
		_t_namebuf[_PT_NAME_TEST_MAX - 1] = '\0';                                                              \
		for (unsigned int _pidx = 0; _pidx < (sizeof(_params) / sizeof(_params[0])); ++_pidx) {                \
			snprintf(_t_namebuf, sizeof(_t_namebuf) - 1, "%s: %d", _name, _pidx);                          \
			pt_add_test_w_param(_func, &_params[_pidx], _t_namebuf, _suite);                               \
		}                                                                                                      \
	} while (0);

void pt_assert_run(int result, const char *expr, const char *func, const char *file, int line);

void pt_add_test(void (*func)(void), const char* name, const char* suite);
void pt_add_test_w_param(void (*func)(const void*), const void *param, const char *name, const char *suite);
void pt_add_suite(void (*func)(void));
int pt_run(void);

#endif
