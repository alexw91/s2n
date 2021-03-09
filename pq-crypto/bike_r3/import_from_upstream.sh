#!/bin/bash
set -ex

# Delete old copy if we have one
if [ -d  "bike-kem" ]; then
	rm -rf ./bike-kem
fi

# Download latest copy of BIKE
git clone git@github.com:awslabs/bike-kem.git

