#!/usr/bin/env bash

wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.0.0.tar.gz
tar -xvf libressl-4.0.0.tar.gz
cd libressl-4.0.0
mkdir build
cd build
cmake ..
make
make test
