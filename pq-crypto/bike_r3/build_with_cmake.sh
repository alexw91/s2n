#!/bin/bash
set -ex

INITIAL_DIR=`pwd`

# Delete old directories if we have any
if [ -d  "bike-kem/build" ]; then
	rm -rf ./bike-kem/build
fi

if [ -d  "objs" ]; then
	rm -rf ./objs
fi

if [ -d  "lib" ]; then
	rm -rf ./lib
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

# Copy .o object files into ./objs folder
cd ${INITIAL_DIR}
mkdir objs
find ./bike-kem/build/CMakeFiles/ -type f -name '*.o' -exec cp {} ./objs \;

# Copy .a static library into ./lib folder
mkdir lib
cp ./bike-kem/build/libbike_r3.a ./lib
