#!/bin/bash

set -x
set -euo pipefail

# Change to the top dir
cd "$(dirname "$0")/.."

# Create a scratch directory
SCRATCH_DIR="$(mktemp -d)"
trap 'rm -rf -- "$SCRATCH_DIR"' EXIT

# Create our extended builder image, based on upstream's builder image.
# Note that the upstream image runs a new bash *login* shell (as the envoybuild
# user) so any modifications to PATH or LD_LIBRARY_PATH in this Dockerfile will
# not be  present in that user's environment in the container. Therefore, we
# just set environment variables with different names, which subsequent
# scripts such as openssl/do_ci.sh pick up and use to modify the actual PATH
# and LD_LIBRARY_PATH variables appropriately inside the container.
docker build --pull --iidfile "${SCRATCH_DIR}/iid" -f - "${SCRATCH_DIR}" << EOF
    FROM $(./ci/run_envoy_docker.sh 'echo $ENVOY_BUILD_IMAGE')

    # Install the missing Kitware public key
    RUN wget -qO- https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - > /usr/share/keyrings/kitware-archive-keyring.gpg
    RUN sed -i "s|^deb.*kitware.*$|deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ \$(lsb_release -cs) main|g" /etc/apt/sources.list
    RUN apt update

    # Install Go Binaries
    RUN wget -qO- https://go.dev/dl/go1.19.11.linux-amd64.tar.gz | tar xz -C /usr/local
    ENV ENVOY_OPENSSL_PATH=/usr/local/go/bin

    # Install OpenSSL 3.0.x
    RUN apt install -y build-essential checkinstall zlib1g-dev
    RUN wget -qO- https://github.com/openssl/openssl/releases/download/openssl-3.0.8/openssl-3.0.8.tar.gz | tar xz -C /
    RUN cd /openssl-3.0.8 && ./config -d --prefix=/usr/local/openssl-3.0.8 --openssldir=/usr/local/openssl-3.0.8
    RUN make -C /openssl-3.0.8 -j && make -C /openssl-3.0.8 install_sw
    ENV OPENSSL_ROOT_DIR=/usr/local/openssl-3.0.8
    ENV ENVOY_OPENSSL_LD_LIBRARY_PATH=\$OPENSSL_ROOT_DIR/lib64
EOF


# Build with libstdc++ rather than libc++ because the bssl-compat prefixer tool
# is linked against some of the LLVM libraries which require libstdc++
export ENVOY_STDLIB=libstdc++

# Tell the upstream run_envoy_docker.sh script to us our builder image
export IMAGE_NAME=$(cat "${SCRATCH_DIR}/iid" | cut -d ":" -f 1)
export IMAGE_ID=$(cat "${SCRATCH_DIR}/iid" | cut -d ":" -f 2)

# Hand off to the upstream run_envoy_docker.sh script
exec ./ci/run_envoy_docker.sh "$@"