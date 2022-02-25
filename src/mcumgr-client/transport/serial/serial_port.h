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

#ifndef _SERIAL_PORT_H_
#define _SERIAL_PORT_H_

#ifndef WIN32
typedef int HANDLE;
#endif

HANDLE port_open(const char *name);
int port_setup(HANDLE fd, unsigned long speed);
int port_write_data(HANDLE fd, const void *buf, size_t len);
int port_read_poll(HANDLE fd, char *buf, size_t maxlen, int end_time,
                   int verbose);

void port_close(HANDLE fd);

int time_get(void);

#endif
