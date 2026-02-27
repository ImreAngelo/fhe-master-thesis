#!/usr/bin/sh
cd vendors/openfhe-development
mkdir build && cd build
cmake ..
make install