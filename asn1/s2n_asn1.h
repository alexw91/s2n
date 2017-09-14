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

#pragma once

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"

/*
 * ASN.1 allows for the representation of arbitrary Nested Data Structures.
 *
 *
 *
 */
/* Bits 7-8 */
#define ASN1_TYPE_CLASS_MASK 0xC0

/* Bit 6 */
#define ASN1_TYPE_ENCODING_MASK 0x20

/* Bits 1-5 */
#define ASN1_TYPE_TAG_MASK 0x1F


/* Bit 8 */
#define ASN1_VARIABLE_LENGTH_MASK 0x80

/* Bits 1-7 */
#define ASN1_LENGTH_OF_LENGTH_MASK 0x7F

typedef enum {
    ASN1_Class_Universal = 0x00,
    ASN1_Class_Context_Specific = 0x80,
    ASN1_Class_Application = 0x40,
    ASN1_Class_Private = 0xC0
} s2n_asn1_type_class;

typedef enum {
    ASN1_Encoded_Primitive = 0x0,
    ASN1_Encoded_Structure = 0x20
} s2n_asn1_type_encoding;

typedef enum {
    ASN1_Tag_Boolean = 0x01,
    ASN1_Tag_Integer = 0x02,
    ASN1_Tag_BitString = 0x03,
    ASN1_Tag_OctectString = 0x04,
    ASN1_Tag_Null = 0x05,
    ASN1_Tag_ObjectIdentifier = 0x06,
    ASN1_Tag_ObjectDescriptor = 0x07,
    ASN1_Tag_External = 0x08,
    ASN1_Tag_Real = 0x09,
    ASN1_Tag_Sequence = 0x10,
    ASN1_Tag_Set = 0x11,
    ASN1_Tag_NumericString = 0x12,
    ASN1_Tag_PrintableString = 0x13,
    ASN1_Tag_T61String = 0x14,
    ASN1_Tag_VideotexString = 0x15,
    ASN1_Tag_IA5String = 0x16,
    ASN1_Tag_UTCTime = 0x17,
    ASN1_Tag_GeneralizedTime = 0x18,
    ASN1_Tag_GraphicString = 0x019,
    ASN1_Tag_VisibleString = 0x10,
    ASN1_Tag_GeneralString = 0x1a,
    ASN1_Tag_UniverisalString = 0x1b,
    ASN1_Tag_BMPString = 0x1c,
} s2n_asn1_type_tag;

struct s2n_asn1_node {
    struct s2n_blob raw;

    s2n_asn1_type_class class;
    s2n_asn1_type_encoding encoding;
    s2n_asn1_type_tag tag;

    /* Child is another node if (encoding == ASN1_Encoded_Structure) */
    union {
       struct s2n_blob value;
       struct s2n_asn1_node *node;
    } child;

    struct s2n_asn1_node *next;
};

int s2n_asn1_parse_stuffer(struct s2n_stuffer *in, struct s2n_asn1_node* out);
