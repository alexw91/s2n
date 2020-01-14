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

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_rsa_pss.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "utils/s2n_random.h"


int s2n_flip_random_bit(struct s2n_blob *blob) {
    /* Flip a random bit in the blob */
    int64_t byte_flip_pos = s2n_public_random(blob->size);
    int64_t bit_flip_pos =  s2n_public_random(8);

    uint8_t mask = 0x01 << (uint8_t)bit_flip_pos;
    blob->data[byte_flip_pos] ^= mask;

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if RSA_PSS_SUPPORTED
    /* Positive Test, ensure "verify(sign(message))" for random message is validated correctly */
    {
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
    }


    /* Negative Test, Loading mismatching RSA PSS Public/Private Keys will fail */
    {
        struct s2n_config *server_config;
        char *cert_chain_pem;
        char *private_key_pem;
        struct s2n_cert_chain_and_key *chain_and_key;
        struct s2n_pkey public_key = {0};

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

        /* Incorrectly reading the CA's Private Key from disk, not the Leaf's Private Key */
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());

        /* Attempting to Load RSA_PSS Certificate with wrong RSA_PSS Key should fail */
        EXPECT_FAILURE(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));

        /* Release Resources */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_pkey_free(&public_key));
        free(cert_chain_pem);
        free(private_key_pem);
    }


    /* Negative Test, rejected if signature modified */
    {
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
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());

        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_cert_chain(chain_and_key, cert_chain_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_private_key(chain_and_key, private_key_pem));

        /* Parse the leaf cert for the public key and certificate type */
        EXPECT_SUCCESS(s2n_asn1der_to_public_key_and_type(&public_key, &pkey_type, &chain_and_key->cert_chain->head->raw));
        S2N_ERROR_IF(pkey_type == S2N_PKEY_TYPE_UNKNOWN, S2N_ERR_CERT_TYPE_UNSUPPORTED);
        EXPECT_SUCCESS(s2n_cert_set_cert_type(chain_and_key->cert_chain->head, pkey_type));

        struct s2n_pkey *private_key = chain_and_key->private_key;
        {
            EXPECT_NOT_NULL(public_key.key.rsa_pss_key.pkey);
            EXPECT_NOT_NULL(private_key);
            EXPECT_NOT_NULL(private_key->key.rsa_pss_key.pkey);

            /* Generate a random blob to sign and verify */
            s2n_stack_blob(random_data, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE);
            EXPECT_SUCCESS(s2n_get_private_random_data(&random_data));

            /* Sign/Verify API's only accept Hashes, so hash our Random Data */
            DEFER_CLEANUP(struct s2n_hash_state sign_hash = {0}, s2n_hash_free);
            DEFER_CLEANUP(struct s2n_hash_state verify_hash = {0}, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&sign_hash));
            EXPECT_SUCCESS(s2n_hash_new(&verify_hash));
            EXPECT_SUCCESS(s2n_hash_init(&sign_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_init(&verify_hash, S2N_HASH_SHA256));
            EXPECT_SUCCESS(s2n_hash_update(&sign_hash, random_data.data, random_data.size));
            EXPECT_SUCCESS(s2n_hash_update(&verify_hash, random_data.data, random_data.size));

            /* Sign and Verify the Hash of the Random Blob */
            s2n_stack_blob(signature_data, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE);
            EXPECT_SUCCESS(s2n_rsa_pss_sign(private_key, &sign_hash, &signature_data));

            /* Flip a random bit in the signature */
            EXPECT_SUCCESS(s2n_flip_random_bit(&signature_data));

            EXPECT_FAILURE(s2n_rsa_pss_verify(&public_key, &verify_hash, &signature_data));
        }

        /* Release Resources */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_pkey_free(&public_key));
        free(cert_chain_pem);
        free(private_key_pem);
    }
#endif

    END_TEST();
}
