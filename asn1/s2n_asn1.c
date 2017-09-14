/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "asn1/s2n_asn1.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

#include <stdio.h>

int s2n_asn1_parse_variable_len(struct s2n_stuffer *in, uint32_t *out_len)
{
    uint8_t raw_len;
    GUARD(s2n_stuffer_read_uint8(in, &raw_len));

    uint32_t parsed_len = 0;

    if ((raw_len & ASN1_VARIABLE_LENGTH_MASK) == 0) {
        /* If variable length bit isn't set, the raw length is the actual length */
        parsed_len = raw_len;
    } else {
        /* Otherwise, if the highest bit is 1, then raw_len is the length in bytes of the length */
        uint8_t len_of_len = raw_len & ASN1_LENGTH_OF_LENGTH_MASK;

        /* If the length can't fit in 32 bits (4 GB), return an error */
        if (sizeof(parsed_len) < len_of_len) {
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }

        uint8_t parsed_len_8bit;
        uint16_t parsed_len_16bit;
        uint32_t parsed_len_24bit;
        uint32_t parsed_len_32bit;

        /* How many bytes are is the length field? */
        switch (len_of_len) {
            case 0:
                parsed_len = 0;
                break;
            case 1:
                s2n_stuffer_read_uint8(in, &parsed_len_8bit);
                parsed_len = parsed_len_8bit;
                break;
            case 2:
                s2n_stuffer_read_uint16(in, &parsed_len_16bit);
                parsed_len = parsed_len_16bit;
                break;
            case 3:
                s2n_stuffer_read_uint24(in, &parsed_len_24bit);
                parsed_len = parsed_len_24bit;
                break;
            case 4:
                s2n_stuffer_read_uint32(in, &parsed_len_32bit);
                parsed_len = parsed_len_32bit;
                break;
            default:
                S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }
    }

    *out_len = parsed_len;
    return 0;
}


int s2n_asn1_parse_stuffer(struct s2n_stuffer *in, struct s2n_asn1_node *out)
{
    uint8_t *start = in->blob.data + in->read_cursor;

    /* Type */
    uint8_t raw_type;
    GUARD(s2n_stuffer_read_uint8(in, &raw_type));

    /* The Raw Type is actually 3 different fields, the class, encoding, and tag */
    out->class =    (raw_type & ASN1_TYPE_CLASS_MASK);
    out->encoding = (raw_type & ASN1_TYPE_ENCODING_MASK);
    out->tag =      (raw_type & ASN1_TYPE_TAG_MASK);

    /* Length */
    uint32_t len;
    GUARD(s2n_asn1_parse_variable_len(in, &len));

    /* Value */
    struct s2n_blob value;
    value.data = s2n_stuffer_raw_read(in, len);
    value.size = len;
    notnull_check(value.data);

    /* Raw Data */
    uint8_t *end = (in->blob.data + in->read_cursor);
    out->raw.data = start;
    out->raw.size = end - start;

    /* Child */
    if (out->encoding == ASN1_Encoded_Primitive) {
        out->child.value = value;
    } else {
        struct s2n_stuffer child_stuffer;
        GUARD(s2n_stuffer_init(&child_stuffer, &value));
        GUARD(s2n_stuffer_skip_write(&child_stuffer, value.size));
        out->child.node = malloc(sizeof(struct s2n_asn1_node));
        notnull_check(out->child.node);
        GUARD(s2n_asn1_parse_stuffer(&child_stuffer, out->child.node));
    }

    /* Next */
    if (s2n_stuffer_data_available(in) > 0) {
        out->next = malloc(sizeof(struct s2n_asn1_node));
        notnull_check(out->next);
        GUARD(s2n_asn1_parse_stuffer(in, out->next));
    }

    return 0;
}
