#!/bin/bash
# Snort 3 Installation Script (Root Version)
# This script automates the installation of Snort 3 and its dependencies
# Note: This script must be run as root

# Exit on error and print commands
set -ex

# Verify root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Update system and install dependencies
apt-get update && apt-get dist-upgrade -y

apt-get install -y libtool automake

apt-get install build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdnet-dev libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev libfl-dev -y

apt-get install -y \
    build-essential \
    libpcap-dev \
    libpcre3-dev \
    libpcre2-dev \
    libnet1-dev \
    zlib1g-dev \
    luajit \
    hwloc \
    libdnet-dev \
    libdumbnet-dev \
    bison \
    flex \
    liblzma-dev \
    openssl \
    libssl-dev \
    pkg-config \
    libhwloc-dev \
    cmake \
    cpputest \
    libsqlite3-dev \
    uuid-dev \
    libcmocka-dev \
    libnetfilter-queue-dev \
    libmnl-dev \
    autotools-dev \
    libluajit-5.1-dev \
    libunwind-dev \
    libfl-dev \
    git \
    wget \
    unzip

# Create and enter source directory
mkdir -p ~/snort_src
cd ~/snort_src

# Install libdaq
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make -j$(nproc)
make install
cd ..

# Install gperftools
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
tar xzf gperftools-2.9.1.tar.gz
cd gperftools-2.9.1
./configure
make -j$(nproc)
make install
cd ..

# Install Snort 3
wget https://github.com/snort3/snort3/archive/refs/heads/master.zip
unzip master.zip
cd snort3-master
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make -j$(nproc)
make install
cd ../..

# Update shared libraries
ldconfig

# Verify installation
if snort -V; then
    echo "Snort 3 installation completed successfully!"
else
    echo "Snort 3 installation failed!"
    exit 1
fi
