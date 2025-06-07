#!/bin/bash

set -x
set -euo pipefail

# Change to the top dir
cd "$(dirname "$0")/.."

# Create a scratch directory
SCRATCH_DIR="../tmp"
# trap 'rm -rf -- "$SCRATCH_DIR"' EXIT

# Create our extended builder image, based on upstream's builder image.
docker build --network host --iidfile "${SCRATCH_DIR}/iid" -f - "${SCRATCH_DIR}" << EOF
    FROM envoyproxy/envoy-build-ubuntu:latest

    # Install the missing Kitware public key
    RUN wget -qO- https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - > /usr/share/keyrings/kitware-archive-keyring.gpg
    RUN sed -i "s|^deb.*kitware.*$|deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ \$(lsb_release -cs) main|g" /etc/apt/sources.list
    # Update the expired xubuntu key
    RUN wget -q -O - https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/devel_kubic_libcontainers_stable.gpg > /dev/null

    RUN apt update

    RUN apt install -y patchelf
    RUN apt install -y vim
    RUN apt-get install -y libtool autoconf automake pkg-config libpsl-dev

    # Install OpenSSL 3.0.x
    ENV OPENSSL_VERSION=3.0.3
    ENV OPENSSL_ROOTDIR=/usr/local/tongsuo
    RUN apt install -y build-essential checkinstall zlib1g-dev
    RUN apt install perl
    RUN wget -qO- https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/8.4.0.tar.gz | tar xz -C /

    RUN cd Tongsuo-8.4.0 && ./Configure --prefix=/usr/local/tongsuo enable-ntls && make -j && make install
    RUN echo "/usr/local/tongsuo/lib64" > /etc/ld.so.conf.d/tongsuo.conf
    RUN ldconfig

    RUN apt install -y sed
    RUN sed -i '/^PATH=/ s/"$/:\/usr\/local\/tongsuo\/bin"/' /etc/environment
    RUN source /etc/environment


    # 下载envoy-openssl源码
    RUN git clone https://github.com/envoyproxy/envoy-openssl.git /source
    WORKDIR /source

    # 创建build目录
    RUN mkdir -p /build
EOF


# Build with libstdc++ rather than libc++ because the bssl-compat prefixer tool
# is linked against some of the LLVM libraries which require libstdc++
export ENVOY_STDLIB=libstdc++

# Tell the upstream run_envoy_docker.sh script to us our builder image
export IMAGE_NAME=$(cat "${SCRATCH_DIR}/iid" | cut -d ":" -f 1)
export IMAGE_ID=$(cat "${SCRATCH_DIR}/iid" | cut -d ":" -f 2)

# Hand off to the upstream run_envoy_docker.sh script
exec ./ci/run_envoy_docker.sh "$@"