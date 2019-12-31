/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>
#include <s2n.h>
#include <openssl/evp.h>

#include "crypto/s2n_hash.h"
#include "utils/s2n_blob.h"

#if S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0) && !defined(LIBRESSL_VERSION_NUMBER)
#define RSA_PSS_SUPPORTED 1
#else
#define RSA_PSS_SUPPORTED 0
#endif

/* Forward declaration to avoid the circular dependency with s2n_pkey.h */
struct s2n_pkey;

#if RSA_PSS_SUPPORTED

struct s2n_rsa_pss_key {
    EVP_PKEY *pkey;
};

extern int s2n_rsa_pss_pkey_init(struct s2n_pkey *pkey);
extern int s2n_evp_pkey_to_rsa_pss_public_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey);
extern int s2n_evp_pkey_to_rsa_pss_private_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey);

#endif
