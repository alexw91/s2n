#!/bin/bash
set -ex

# Delete old copy if we have one
if [ -d  "bike-kem/build" ]; then
	rm -rf ./bike-kem/build
fi

# Set up build directory
cd bike-kem
mkdir build
cd build

# Compile Bike Round 3
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j

# Run Tests
./bike-test
