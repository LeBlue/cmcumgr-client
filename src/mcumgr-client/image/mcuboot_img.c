/*
 * Copyright (c) 2022 Matthias Wauer
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <errno.h>

#include "byteordering.h"
#include "mcumgr-client/mcuboot_img.h"
#include "mcumgr-client/file_reader.h"

#define IMAGE_MAGIC                 0x96f3b83d

#define IMAGE_HEADER_SIZE           32


/** Image header offset 0.  All fields are in little endian byte order. */
struct mcuboot_image_hdr {
    uint32_t magic;
    uint32_t load_addr;
    uint16_t hdr_size;           /* Size of image header (bytes). */
    uint16_t protect_tlv_size;   /* Size of protected TLV area (bytes). */
    uint32_t img_size;           /* Does not include header. */
    uint32_t flags;              /* IMAGE_F_[...]. */
    struct image_version version;
    uint32_t _pad1;
};


#define IMAGE_TLV_INFO_MAGIC        0x6907
#define IMAGE_TLV_PROT_INFO_MAGIC   0x6908

/** Image TLV header.  All fields in little endian. */
struct mcuboot_image_tlv_info {
    uint16_t magic;
    uint16_t tlv_tot;  /* size of TLV area (including tlv_info header) */
};

/** Image trailer TLV format. All fields in little endian. */
struct mcuboot_image_tlv {
    uint8_t  type;   /* IMAGE_TLV_[...]. */
    uint8_t  _pad;
    uint16_t len;    /* Data length (not including TLV header). */
};

/*
 * Image header flags.
 */
#define IMAGE_F_PIC                      0x00000001 /* Not supported. */
#define IMAGE_F_ENCRYPTED_AES128         0x00000004 /* Encrypted using AES128. */
#define IMAGE_F_ENCRYPTED_AES256         0x00000008 /* Encrypted using AES256. */
#define IMAGE_F_NON_BOOTABLE             0x00000010 /* Split image app. */
#define IMAGE_F_RAM_LOAD                 0x00000020

/*
 * Image trailer TLV types.
 */
#define IMAGE_TLV_KEYHASH           0x01   /* hash of the public key */
#define IMAGE_TLV_SHA256            0x10   /* SHA256 of image hdr and body */
#define IMAGE_TLV_RSA2048_PSS       0x20   /* RSA2048 of hash output */
#define IMAGE_TLV_ECDSA224          0x21   /* ECDSA of hash output */
#define IMAGE_TLV_ECDSA256          0x22   /* ECDSA of hash output */
#define IMAGE_TLV_RSA3072_PSS       0x23   /* RSA3072 of hash output */
#define IMAGE_TLV_ED25519           0x24   /* ED25519 of hash output */
#define IMAGE_TLV_ENC_RSA2048       0x30   /* Key encrypted with RSA-OAEP-2048 */
#define IMAGE_TLV_ENC_KW            0x31   /* Key encrypted with AES-KW-128 or 256 */
#define IMAGE_TLV_ENC_EC256         0x32   /* Key encrypted with ECIES-P256 */
#define IMAGE_TLV_ENC_X25519        0x33   /* Key encrypted with ECIES-X25519 */
#define IMAGE_TLV_DEPENDENCY        0x40   /* Image depends on other image */
#define IMAGE_TLV_SEC_CNT           0x50   /* security counter */

#define TLV_MAX_DATA_LEN 32


int mcuboot_image_magic_ok(const struct mcuboot_image_hdr *img_hdr)
{
    return (le32_to_host(img_hdr->magic) == IMAGE_MAGIC);
}

int mcuboot_image_valid(const struct mcuboot_image_hdr *img_hdr)
{
    return mcuboot_image_magic_ok(img_hdr);
}

uint32_t mcuboot_image_get_tlv_offset(const struct mcuboot_image_hdr *img_hdr)
{
    return le16_to_host(img_hdr->hdr_size) + le32_to_host(img_hdr->img_size);
}

uint32_t mcuboot_image_get_image_size(const struct mcuboot_image_hdr *img_hdr)
{
    return le32_to_host(img_hdr->img_size);
}

int mcuboot_image_load_addr_valid(const struct mcuboot_image_hdr *img_hdr)
{
    if (img_hdr->flags & IMAGE_F_RAM_LOAD)
        return 1;
    return 0;
}


void mcuboot_image_get_version(const struct mcuboot_image_hdr *img_hdr, struct image_version *version)
{
    version->major = img_hdr->version.major;
    version->minor = img_hdr->version.minor;
    version->revision = le16_to_host(img_hdr->version.revision);
    version->build_num = le32_to_host(img_hdr->version.build_num);
}

void mcuboot_image_get_image_hash(const struct mcuboot_image_hdr *img_hdr)
{
    (void)img_hdr;
}

void mcuboot_image_tlv_parse(const struct mcuboot_image_hdr *img_hdr)
{
    (void)img_hdr;
}

static int tlv_info_valid(const struct mcuboot_image_tlv_info *tlv_info)
{
    return (tlv_info->magic == le16_to_host(IMAGE_TLV_INFO_MAGIC));
}

static uint16_t tlv_info_total_len(const struct mcuboot_image_tlv_info *tlv_info)
{
    return le16_to_host(tlv_info->tlv_tot);
}

static uint8_t tlv_hdr_type(const struct mcuboot_image_tlv *tlv_hdr)
{
    return tlv_hdr->type;
}

static uint16_t tlv_hdr_len(const struct mcuboot_image_tlv *tlv_hdr)
{
    return le16_to_host(tlv_hdr->len);
}


int mcuboot_image_file_parse(struct file_reader *reader, struct mcuboot_image *image_info)
{
    int rc;
    size_t readlen;
    if (!reader || !reader->fh || !image_info) {
        return -EINVAL;
    }
    rc = reader->op->open(reader->fh);
    if (rc) {
        return rc;
    }

    /* read image header */
    struct mcuboot_image_hdr img_hdr;
    readlen = sizeof(img_hdr);
    rc = reader->op->read(reader->fh, (uint8_t*) &img_hdr, &readlen, 0);
    if (rc < 0) {
        return rc;
    } else if (readlen) {
        rc = -ENODATA;
        goto err_close;
    }
    if (!mcuboot_image_valid(&img_hdr)) {
        rc = -ENODATA;
        goto err_close;
    }

    image_info->magic_ok = 1;

    mcuboot_image_get_version(&img_hdr, &image_info->version);

    image_info->img_sz = mcuboot_image_get_image_size(&img_hdr);
    image_info->file_sz = sizeof(img_hdr) + image_info->img_sz;

    /* read TLV info */
    uint32_t tlv_info_offset = mcuboot_image_get_tlv_offset(&img_hdr);
    struct mcuboot_image_tlv_info tlv_info;
    readlen = sizeof(tlv_info);

    rc = reader->op->read(reader->fh, (uint8_t*) &tlv_info, &readlen, tlv_info_offset);
    if (rc < 0) {
        goto err_close;
    } else if (rc < (int)sizeof(tlv_info)) {
        rc = -ENODATA;
        goto err_close;
    }
    if (!tlv_info_valid(&tlv_info)) {
        rc = -ENODATA;
        goto err_close;
    }
    uint16_t tlv_info_size = tlv_info_total_len(&tlv_info);

    uint32_t tlv_end = tlv_info_offset + tlv_info_size;
    uint32_t tlv_off = tlv_info_offset + sizeof(tlv_info);
    image_info->file_sz = tlv_off;

    /* loop over TLV entries */
    while (tlv_off < tlv_end) {
        struct mcuboot_image_tlv tlv_hdr;
        readlen = sizeof(tlv_hdr);
        rc = reader->op->read(reader->fh, (uint8_t*) &tlv_hdr, &readlen, tlv_off);
        if (rc < 0) {
            goto err_close;
        } else if (rc < (int)sizeof(tlv_hdr)) {
            rc = -ENODATA;
            goto err_close;
        }
        uint16_t tlv_data_len = tlv_hdr_len(&tlv_hdr);

        /* advance to data */
        tlv_off += sizeof(tlv_hdr);
        image_info->file_sz += sizeof(tlv_hdr);

        switch (tlv_hdr_type(&tlv_hdr)) {
            case IMAGE_TLV_SHA256:
            {
                if (tlv_data_len == sizeof(image_info->hash)) {
                    readlen = sizeof(image_info->hash);
                    rc = reader->op->read(reader->fh, image_info->hash, &readlen, tlv_off);
                    if (rc < 0) {
                        goto err_close;
                    } else if (rc < tlv_data_len) {
                        rc = -ENODATA;
                        goto err_close;
                    }
                } else {
                    rc = -ENODATA;
                    goto err_close;
                }
                break;
            }
            /* no other decoding needed/supported, read and skip to validate tlv entries are complete */
            default:
                if (tlv_data_len > 0) {
                    uint8_t tmpbuf;
                    readlen = 1;
                    rc = reader->op->read(reader->fh, &tmpbuf, &readlen, tlv_off + tlv_data_len - 1);
                    if (rc < 0) {
                        goto err_close;
                    } else if (rc < 1) {
                        rc = -ENODATA;
                        goto err_close;
                    }
                }
                break;
        }
        /* advance to next entry */
        tlv_off += tlv_data_len;
        image_info->file_sz += tlv_data_len;
    }

    rc = 0;
err_close:
    reader->op->close(reader->fh);

    return rc;
}
