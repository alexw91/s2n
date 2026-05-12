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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api/s2n.h"
#include "tls/policy/s2n_policy_feature.h"
#include "tls/s2n_security_policies.h"

static int usage()
{
    printf("policy <version> [format]\n"
           "  format: debug_v1 (default), S2N_POLICY_FORMAT_DIFFABLE_V1\n"
           "example: policy default_tls13\n"
           "example: policy default_tls13 S2N_POLICY_FORMAT_DIFFABLE_V1\n\n");
    return 0;
}

static s2n_policy_format parse_format(const char *format_str)
{
    if (strcmp(format_str, "S2N_POLICY_FORMAT_DIFFABLE_V1") == 0) {
        return S2N_POLICY_FORMAT_DIFFABLE_V1;
    }
    if (strcmp(format_str, "S2N_POLICY_FORMAT_DEBUG_V1") == 0) {
        return S2N_POLICY_FORMAT_DEBUG_V1;
    }
    return S2N_POLICY_FORMAT_DEBUG_V1;
}

int main(int argc, char *const *argv)
{
    if (argc < 2 || argc > 3) {
        usage();
        exit(1);
    }

    if (s2n_init() != S2N_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize s2n\n");
        exit(1);
    }

    const char *policy_name = argv[1];
    s2n_policy_format format = S2N_POLICY_FORMAT_DEBUG_V1;
    if (argc == 3) {
        format = parse_format(argv[2]);
    }

    const struct s2n_security_policy *policy = NULL;
    if (s2n_find_security_policy_from_version(policy_name, &policy) != S2N_SUCCESS) {
        fprintf(stderr, "Error: Failed to find security policy\n");
        s2n_cleanup();
        exit(1);
    }

    uint32_t output_size = 0;
    if (s2n_security_policy_write_fd(policy, format, STDOUT_FILENO, &output_size) != S2N_SUCCESS) {
        s2n_cleanup();
        exit(1);
    }

    s2n_cleanup();
    return 0;
}
