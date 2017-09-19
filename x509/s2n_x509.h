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

/*
 * From: https://tools.ietf.org/html/rfc2459#section-4.1
 *
 * Certificate  ::=  SEQUENCE  {
 *     tbsCertificate       TBSCertificate,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING
 * }
 *
 * TBSCertificate  ::=  SEQUENCE  {
 *     version         [0]  EXPLICIT Version DEFAULT v1,
 *     serialNumber         CertificateSerialNumber,
 *     signature            AlgorithmIdentifier,
 *     issuer               Name,
 *     validity             Validity,
 *     subject              Name,
 *     subjectPublicKeyInfo SubjectPublicKeyInfo,
 *     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                          -- If present, version shall be v2 or v3
 *     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                          -- If present, version shall be v2 or v3
 *     extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                          -- If present, version shall be v3
 * }
 *
 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 *
 * CertificateSerialNumber  ::=  INTEGER
 *
 * Validity ::= SEQUENCE {
 *     notBefore      Time,
 *     notAfter       Time
 * }
 *
 * Time ::= CHOICE {
 *     utcTime        UTCTime,
 *     generalTime    GeneralizedTime
 * }
 *
 * UniqueIdentifier  ::=  BIT STRING
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *     algorithm            AlgorithmIdentifier,
 *     subjectPublicKey     BIT STRING
 * }
 *
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension  ::=  SEQUENCE  {
 *     extnID      OBJECT IDENTIFIER,
 *     critical    BOOLEAN DEFAULT FALSE,
 *     extnValue   OCTET STRING
 * }
 *
 * AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm OBJECT IDENTIFIER,
 *     parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * Name ::= CHOICE { RDNSequence }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
 *
 * AttributeType ::= OBJECT IDENTIFIER
 *
 * AttributeValue ::= ANY DEFINED BY AttributeType
 *
 */

typedef enum {
    CommonName,
    CountryName,
    LocalityName,
    StateOrProvinceName,
    OrganizationalName,
    OrganizationalUnitName,
    Unknown
} s2n_x509_name_type;

typedef enum {
    RSA,
    DiffieHellman
} s2n_x509_algorithm_id;

typedef enum {
    SubjectAltName,
    IssuerAltName,
    KeyUsage,
    Unknown
} s2n_x509_extension_type;

struct s2n_x509_extension {
    s2n_x509_extension_type type;
    struct s2n_blob id;
    struct s2n_blob value;
    struct s2n_x509_extension *next;
};

struct s2n_x509_extension_list {
    struct s2n_asn1_node *raw_asn1;
    struct s2n_x509_extension *start;
};

struct s2n_x509_name_element {
    s2n_x509_name_type type;
    struct s2n_blob id;
    struct s2n_blob value;
    struct s2n_x509_name_element *next;
};

struct s2n_x509_name_list {
    struct s2n_asn1_node *raw_asn1;
    struct s2n_x509_name_element *start;
};

struct s2n_x509_validity_period {
    time_t not_before;
    time_t not_after;
};

struct s2n_public_key_info {
    s2n_x509_algorithm_id alg;
    struct s2n_blob public_key;
};

struct s2n_tbs_x509_cert {
    struct s2n_asn1_node *raw_asn1;
    uint8_t cert_version;
    struct s2n_blob serial_number;
    struct s2n_x509_algorithm_id sig_alg;
    struct s2n_x509_name_list issuer_name;
    struct s2n_x509_validity_period validity_period;
    struct s2n_x509_name_list subject_name;
    struct s2n_public_key_info subject_public_key;
    struct s2n_blob issuer_unique_id;
    struct s2n_blob subject_unique_id;
    struct s2n_x509_extension_list extensions;
};

struct s2n_x509_cert {
    struct s2n_asn1_node *raw_asn1;
    struct s2n_tbs_x509_cert tbs_cert;
    struct s2n_x509_algorithm_id sig_alg;
    struct s2n_blob signature;
};
