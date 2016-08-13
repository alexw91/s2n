#!/bin/bash
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

S2ND_PORT="8888"
S2ND_HOST="127.0.0.1"

echo "Starting s2nd in the background..."
# Run s2nd job in the background
../../bin/s2nd -c test_all $S2ND_HOST $S2ND_PORT &

#Give s2nd time to start up
sleep 3s

# Modified from https://dwradcliffe.com/2014/10/16/testing-tls-fallback.html
OPENSSL_OUTPUT=`openssl s_client -connect $S2ND_HOST:$S2ND_PORT -fallback_scsv -no_tls1_1`

# Kill s2nd (the last job executed in the background)
kill $!

FAILED_TLS_FALLBACK_TEST=0

# If OpenSSL was able to successfully connect, consider that a failure
echo $OPENSSL_OUTPUT | grep -qi "CONNECTED" && FAILED_TLS_FALLBACK_TEST=1

#If OpenSSL did not return a TLS inappropriate fallback alert, consider that a failure
echo $OPENSSL_OUTPUT | grep -qi "alert inappropriate fallback" || FAILED_TLS_FALLBACK_TEST=1

if [ $FAILED_TLS_FALLBACK_TEST == 1 ]; then
	echo "OpenSSL output: $OPENSSL_OUTPUT"
	printf "\033[31;1mFAILED TLS_FALLBACK_SCSV_TEST\033[0m\n"
	exit -1
else
	printf "\033[32;1mPASSED TLS_FALLBACK_SCSV_TEST\033[0m\n"
fi