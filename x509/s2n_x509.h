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
    AlgorithmIdentifier,
    SignatureAlgorithm,
    SignatureValue,
    TBSCert,
    TBSCertVersion,
    TBSCertSerialNumber,
    TBSCertSignature,
    TBSCertIssuerName,
    TBSCertValidityPeriod,
    TBSCertSubjectName,
    TBSCertSubjectPublicKey,
    TBSCertIssuerUniqueId,
    TBSCertSubjectUniqueId,
    TBSCertExtensionList,
    TBSCertExtension
} s2n_x509_node_type;

typedef enum {
    CommonName,
    CountryName,
    LocalityName,
    StateOrProvinceName,
    OrganizationalName,
    OrganizationalUnitName,
} s2n_x509_name_type;

struct s2n_x509_node {
    s2n_x509_node_type type;
    struct s2n_asn1_node *asn1;
};

struct s2n_x509_name {
    s2n_x509_name_type type;
    struct s2n_asn1_node *asn1;
    struct s2n_x509_name *next;
};

struct s2n_tbs_x509_cert {
    struct s2n_x509_node cert_version; /* Optional, if absent assume Version 1 */
    struct s2n_x509_node serial_number;
    struct s2n_x509_node signature;
    struct s2n_x509_name issuer_name;
    struct s2n_x509_node validity_period;
    struct s2n_x509_name subject_name;
    struct s2n_x509_node subject_public_key;
    struct s2n_x509_node issuer_unique_id;
    struct s2n_x509_node subject_unique_id;
    struct s2n_x509_node extensions;
};

struct s2n_x509_cert {
    struct s2n_tbs_x509_cert tbs_cert;
    struct s2n_x509_node sig_alg;
    struct s2n_x509_node sig_value;
};
