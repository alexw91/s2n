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

#include "s2n_test.h"

#include <stdlib.h>
#include <stdio.h>

#include <s2n.h>

#include "asn1/s2n_asn1.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    char *cert_chain_pem;
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_stuffer pem_stuffer, der_stuffer;
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&der_stuffer, 2048));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&pem_stuffer, cert_chain_pem));
    EXPECT_SUCCESS(s2n_stuffer_certificate_from_pem(&pem_stuffer, &der_stuffer));
    struct s2n_asn1_node root;
    EXPECT_SUCCESS(s2n_asn1_parse_stuffer(&der_stuffer, &root));
    END_TEST();
}
