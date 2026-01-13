# Requirements Document

## Introduction

This document specifies the requirements for a new public API `s2n_conn_get_signature_public_key()` that returns a human-readable string describing the certificate signing algorithm and key parameters of the leaf server certificate negotiated during a TLS handshake. This API enables applications to inspect and log the cryptographic properties of the peer's certificate for auditing, debugging, and compliance purposes.

## Glossary

- **Leaf Certificate**: The first certificate in a certificate chain, representing the end-entity (server or client) being authenticated.
- **Public Key Algorithm**: The cryptographic algorithm used for the certificate's public key (RSA, ECDSA, ML-DSA).
- **Key Size**: The bit length of the public key, determining its cryptographic strength.
- **Named Curve**: For ECDSA keys, the specific elliptic curve used (e.g., secp256r1, secp384r1, secp521r1).
- **ML-DSA**: Module-Lattice-Based Digital Signature Algorithm, a post-quantum signature scheme (also known as Dilithium).
- **s2n_connection**: An opaque structure representing a TLS connection in s2n-tls.

## Requirements

### Requirement 1

**User Story:** As a TLS application developer, I want to retrieve a string describing the server's leaf certificate public key algorithm and parameters, so that I can log and audit the cryptographic properties of negotiated connections.

#### Acceptance Criteria

1. WHEN a caller invokes `s2n_conn_get_signature_public_key` with a valid connection and output buffer THEN the System SHALL write a null-terminated string describing the leaf certificate's public key to the output buffer.
2. WHEN the connection parameter is NULL THEN the System SHALL return S2N_FAILURE and set an appropriate error code.
3. WHEN the output buffer parameter is NULL THEN the System SHALL return S2N_FAILURE and set an appropriate error code.
4. WHEN the output buffer size parameter is NULL THEN the System SHALL return S2N_FAILURE and set an appropriate error code.
5. WHEN the TLS handshake has not completed THEN the System SHALL return S2N_FAILURE and set an appropriate error code indicating no certificate is available.

### Requirement 2

**User Story:** As a TLS application developer, I want RSA certificate keys to be formatted with their key size, so that I can identify the RSA key strength.

#### Acceptance Criteria

1. WHEN the leaf certificate uses a 2048-bit RSA key THEN the System SHALL return the string "rsa_2048".
2. WHEN the leaf certificate uses a 3072-bit RSA key THEN the System SHALL return the string "rsa_3072".
3. WHEN the leaf certificate uses a 4096-bit RSA key THEN the System SHALL return the string "rsa_4096".
4. WHEN the leaf certificate uses an RSA key with a non-standard size (not 2048, 3072, or 4096 bits) THEN the System SHALL return a string in the format "rsa_<keysize>" where <keysize> is the actual bit length.
5. WHEN the leaf certificate uses an RSA-PSS key THEN the System SHALL format the output identically to standard RSA keys based on key size.

### Requirement 3

**User Story:** As a TLS application developer, I want ECDSA certificate keys to be formatted with their curve name, so that I can identify the elliptic curve used.

#### Acceptance Criteria

1. WHEN the leaf certificate uses an ECDSA key on the secp256r1 curve THEN the System SHALL return the string "ecdsa_secp256r1".
2. WHEN the leaf certificate uses an ECDSA key on the secp384r1 curve THEN the System SHALL return the string "ecdsa_secp384r1".
3. WHEN the leaf certificate uses an ECDSA key on the secp521r1 curve THEN the System SHALL return the string "ecdsa_secp521r1".

### Requirement 4

**User Story:** As a TLS application developer, I want ML-DSA (post-quantum) certificate keys to be formatted with their security level, so that I can identify the ML-DSA variant used.

#### Acceptance Criteria

1. WHEN the leaf certificate uses an ML-DSA-44 key THEN the System SHALL return the string "mldsa44".
2. WHEN the leaf certificate uses an ML-DSA-65 key THEN the System SHALL return the string "mldsa65".
3. WHEN the leaf certificate uses an ML-DSA-87 key THEN the System SHALL return the string "mldsa87".

### Requirement 5

**User Story:** As a TLS application developer, I want the API to handle buffer size constraints safely, so that I can avoid buffer overflows.

#### Acceptance Criteria

1. WHEN the provided output buffer is too small to hold the result string (including null terminator) THEN the System SHALL return S2N_FAILURE and set an appropriate error code.
2. WHEN the provided output buffer is exactly large enough THEN the System SHALL write the complete null-terminated string and return S2N_SUCCESS.
3. WHEN the provided output buffer is larger than needed THEN the System SHALL write the complete null-terminated string and return S2N_SUCCESS.

### Requirement 6

**User Story:** As a TLS application developer, I want the API to report the actual required buffer size, so that I can allocate an appropriately sized buffer.

#### Acceptance Criteria

1. WHEN the caller provides a size output parameter THEN the System SHALL write the number of bytes written (including null terminator) to that parameter on success.
2. WHEN the buffer is too small THEN the System SHALL write the required buffer size to the size output parameter before returning failure.

### Requirement 7

**User Story:** As a TLS application developer, I want to specify whether I'm requesting the client or server certificate's public key information, so that I can inspect either certificate regardless of my connection mode.

#### Acceptance Criteria

1. WHEN the caller specifies S2N_CLIENT mode THEN the System SHALL return information about the client's leaf certificate public key.
2. WHEN the caller specifies S2N_SERVER mode THEN the System SHALL return information about the server's leaf certificate public key.
3. WHEN the caller specifies S2N_SERVER mode on a client connection after handshake completion THEN the System SHALL return information about the peer (server) certificate.
4. WHEN the caller specifies S2N_CLIENT mode on a server connection where client authentication was performed THEN the System SHALL return information about the peer (client) certificate.
5. WHEN the caller specifies S2N_CLIENT mode but no client certificate was negotiated THEN the System SHALL return S2N_FAILURE and set an appropriate error code.
