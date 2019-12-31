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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_rsa_pss.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"


int main(int argc, char **argv)
{
    BEGIN_TEST();

#if RSA_PSS_SUPPORTED
    struct s2n_config *server_config;
    char *cert_chain_pem;
    char *private_key_pem;
    struct s2n_cert_chain_and_key *chain_and_key;
    struct s2n_pkey public_key = {0};
    s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(server_config = s2n_config_new());

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());

    /* Load the Private Key */
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

    /* Load the Public Key */
    EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&public_key, &pkey_type, &chain_and_key->cert_chain->head->raw));
    EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA_PSS);

    /* Sign and Verify a Random Value to ensure that Public and Private Key Matches */
    EXPECT_SUCCESS(s2n_pkey_match(&public_key, chain_and_key->private_key));

    /* Release Resources */
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_pkey_free(&public_key));
    free(cert_chain_pem);
    free(private_key_pem);
#endif

    END_TEST();
}
