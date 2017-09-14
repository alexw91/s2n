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


/* An OID is a hierarchical namespace of Objects (usually used for named ASN.1 Structures).
 *
 * As an Example, a RSA Public Key has an ASN.1 Structure of:
 *
 *     RSAPublicKey ::= SEQUENCE {
 *         modulus INTEGER,
 *         publicExponent INTEGER
 *     }
 *
 * This ASN.1 Structure is defined as an object in the OID namespace:
 *
 *     "/iso/member-body/us/rsadsi/pkcs/pkcs-1/rsaEncryption"
 *
 * Each of these namespace components can be mapped to an integer in "dot notation":
 *
 *    "1.2.840.113549.1.1.1"
 *
 * And finally this dot-notation can be encoded into a hexadecimal String:
 *
 *    "2A864886F70D010101"
 *
 * For more info, see:
 *  - http://www.oid-info.com/faq.htm
 *  - https://msdn.microsoft.com/en-us/library/bb540809
 *
 */

/* Only defining OID's actually used in x509 */
typedef enum {

    /* Algorithm Identifiers */
    OID_AlgorithmId_RSA,
    OID_AlgorithmId_DiffieHellman,

    /* Distinguished Names */
    OID_Name_CommonName,
    OID_Name_CountryName,
    OID_Name_LocalityName,
    OID_Name_StateOrProvinceName,
    OID_Name_OrganizationName,
    OID_Name_OrganizationalUnitName,

    /* x509 Extensions */
    OID_x509Extension_SubjectAlternativeName,



} s2n_oid_type;

struct s2n_oid_type_encoding {
    s2n_oid_type type;
    const char *hex;
};

static struct s2n_oid_type_encoding OID_ENCODINGS[] = {
    { OID_AlgorithmId_RSA,                              "2A864886F70D010101" },
    { OID_AlgorithmId_DiffieHellman,                    "2A8648CE3E0201" },
    { OID_x509Extension_SubjectAlternativeName,         "551D11"}
};
