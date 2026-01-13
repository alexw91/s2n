/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

/* Maximum buffer size for public key string output */
#define S2N_PUBLIC_KEY_STR_MAX_SIZE 32

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: NULL connection returns S2N_FAILURE with S2N_ERR_NULL */
    {
        char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
        uint32_t output_size = sizeof(output);

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_conn_get_signature_public_key(NULL, S2N_SERVER, output, &output_size),
                S2N_ERR_NULL);
    };

    /* Test: NULL output buffer returns S2N_FAILURE with S2N_ERR_NULL */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        uint32_t output_size = S2N_PUBLIC_KEY_STR_MAX_SIZE;

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_conn_get_signature_public_key(conn, S2N_SERVER, NULL, &output_size),
                S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: NULL output_size returns S2N_FAILURE with S2N_ERR_NULL */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_conn_get_signature_public_key(conn, S2N_SERVER, output, NULL),
                S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: RSA 2048-bit certificate returns "rsa_2048" */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&chain_and_key,
                "rsae", "pkcs", "2048", "sha256"));

        char ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(ca_path, "rsae", "pkcs", "2048", "sha256"));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, ca_path, NULL));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
        uint32_t output_size = sizeof(output);

        EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
        EXPECT_STRING_EQUAL(output, "rsa_2048");
    };

    /* Test: RSA 3072-bit certificate returns "rsa_3072" */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&chain_and_key,
                "rsae", "pkcs", "3072", "sha256"));

        char ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(ca_path, "rsae", "pkcs", "3072", "sha256"));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, ca_path, NULL));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
        uint32_t output_size = sizeof(output);

        EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
        EXPECT_STRING_EQUAL(output, "rsa_3072");
    };

    /* Test: RSA 4096-bit certificate returns "rsa_4096" */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&chain_and_key,
                "rsae", "pkcs", "4096", "sha384"));

        char ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(ca_path, "rsae", "pkcs", "4096", "sha384"));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, ca_path, NULL));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
        uint32_t output_size = sizeof(output);

        EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
        EXPECT_STRING_EQUAL(output, "rsa_4096");
    };

    END_TEST();
}
