/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MCUMGR_CLIENT_H
#define MCUMGR_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>


/* include these as API */
#include "mgmt.h"
#include "mcuboot_img.h"
#include "mgmt_img.h"
#include "mgmt_os.h"
#include "mgmt_utils.h"

#include "cmd_img.h"
#include "cmd_os.h"


/**
 * mcumgr error codes.
 */
#define MGMT_ERR_EOK            0
#define MGMT_ERR_EUNKNOWN       1
#define MGMT_ERR_ENOMEM         2
#define MGMT_ERR_EINVAL         3
#define MGMT_ERR_ETIMEOUT       4
#define MGMT_ERR_ENOENT         5
#define MGMT_ERR_EBADSTATE      6       /* Current state disallows command. */
#define MGMT_ERR_EMSGSIZE       7       /* Response too large. */
#define MGMT_ERR_ENOTSUP        8       /* Command not supported. */
#define MGMT_ERR_ECORRUPT       9       /* Corrupt */
#define MGMT_ERR_EPERUSER       256

#ifdef __cplusplus
extern "C" {
#endif

/* TODO: does this belong here ?*/
int mgmt_parse_version_string(const char *vbuf, struct image_version *version);


#ifdef __cplusplus
}
#endif

#endif