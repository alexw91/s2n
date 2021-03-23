#!/bin/bash
set -ex

# Delete old copy if we have one
if [ -d  "bike-kem" ]; then
	rm -rf ./bike-kem
fi

# Download latest copy of BIKE
git clone git@github.com:awslabs/bike-kem.git

# Prepend the string "BIKE1_L1_R3" to the public "crypto_kem_*()"" API's
find ./bike-kem -type f -name '*.[ch]' -exec sed -i 's/ crypto_kem_/ BIKE1_L1_R3_crypto_kem_/g' {} \;

