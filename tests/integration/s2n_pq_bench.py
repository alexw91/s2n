#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

"""
PQ Handshake tests: s2nd and s2nc negotiate a handshake using BIKE or SIKE KEMs
"""

import argparse
import os
from os import environ
import sys
import subprocess
import timeit

pq_handshake_test_params = [
    # Client and server cipher preference versions are compatible for a successful PQ handshake
    #{"client_ciphers": "KMS-PQ-TLS-1-0-2019-06", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r1-Level1"},
    {"client_ciphers": "ELBSecurityPolicy-TLS-1-1-2017-01", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "None"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r2-Level1"},
    #{"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2019-11", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp503r1-KEM"},
    {"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp434r2-KEM"},
]

def do_pq_handshake(client_ciphers, server_ciphers, host, port, num_times):
    s2nd_cmd = ["../../bin/s2nd", "--negotiate", "--prefer-low-latency", "--ciphers", server_ciphers, host, port]
    s2nc_cmd = ["../../bin/s2nc", "-i", "--ciphers", client_ciphers, host, port]
    current_dir = os.path.dirname(os.path.realpath(__file__))

    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, cwd=current_dir)

    for i in range(0, num_times):
        s2nc = subprocess.Popen(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, cwd=current_dir)
        s2nc.wait()

    s2nd.kill()
    s2nd.wait()

    return 0

def wrapper(func, *args, **kwargs):
    def wrapped():
        return func(*args, **kwargs)
    return wrapped


def main():
    parser = argparse.ArgumentParser(description='Runs PQ handshake integration tests using s2nd and s2nc.')
    parser.add_argument('host', help='The host for s2nd to bind to')
    parser.add_argument('port', type=int, help='The port for s2nd to bind to')
    args = parser.parse_args()
    host = str(args.host)
    port = str(args.port)

    for test_param_set in pq_handshake_test_params:
        client_ciphers = test_param_set["client_ciphers"]
        server_ciphers = test_param_set["server_ciphers"]
        expected_cipher = test_param_set["expected_cipher"]
        expected_kem = test_param_set["expected_kem"]

        num_iters = 1000

        wrapped = wrapper(do_pq_handshake, client_ciphers, server_ciphers, host, port, num_iters)
        print("\nCipher: %-37sKEM: %-20s" % (expected_cipher, expected_kem))
        t = timeit.timeit(wrapped, number=1)
        print(str(num_iters) + " handshakes completed in " + str(t) + " seconds.")
        print("Average: " + str((t / num_iters)*1000) + " ms")

if __name__ == "__main__":
    sys.exit(main())
