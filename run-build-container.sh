#!/bin/bash

set -euo pipefail

ENVOY_OPENSSL_DIR="$(cd "$(dirname "$0")" && pwd)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

DOCKER_IMAGE=$(sed -n 's/^build:docker-sandbox --experimental_docker_image=//p' "${ENVOY_OPENSSL_DIR}/vendor/envoy/.bazelrc")
if [[ -z "${DOCKER_IMAGE}" ]]; then
	echo "Failed to determine builder docker image"
	exit 1
fi


cat << 'EOF' > "${TMP_DIR}/entrypoint.sh"
    #!/bin/bash -e

    sudo chown -R "$(id -u):$(id -g)" $HOME
    export BAZELRC_FILE=$HOME/.bazelrc

    /source/vendor/envoy/bazel/setup_clang.sh /opt/llvm # Writes to $BAZELRC_FILE

    # See https://github.com/envoyproxy/envoy/blob/main/bazel/README.md#config-flag-choices
    echo "build --config=clang" >> $BAZELRC_FILE
    # echo "build --config=libc++" >> $BAZELRC_FILE

    if [ ! -z "$BAZEL_REMOTE_CACHE" ]; then
        echo "build --remote_cache=${BAZEL_REMOTE_CACHE}" >> $BAZELRC_FILE
    fi

    if [ ! -z "$BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER" ]; then
        echo "build --experimental_remote_downloader=${BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER}" >> $BAZELRC_FILE
    fi

    if true; then # Useful for debugging build failures
        echo "build --verbose_failures" >> $BAZELRC_FILE
        echo "build --sandbox_debug" >> $BAZELRC_FILE
        echo "build --experimental_ui_max_stdouterr_bytes=104857600" >> $BAZELRC_FILE
    fi

    exec /bin/bash
EOF


cat << EOF > "${TMP_DIR}/Dockerfile"
    FROM ${DOCKER_IMAGE}

    RUN apt update -y
    RUN apt install -y vim
    RUN apt install -y gawk

    RUN cd /tmp && wget -q https://go.dev/dl/go1.19.11.linux-amd64.tar.gz && \
        tar -C /usr/local -xzf /tmp/go1.19.11.linux-amd64.tar.gz && \
        rm /tmp/go1.19.11.linux-amd64.tar.gz
    ENV PATH=/usr/local/go/bin:\$PATH

    ADD entrypoint.sh /entrypoint.sh
    RUN chmod 755 /entrypoint.sh

    # Install OpenSSL 3.0.8
    RUN apt install -y build-essential checkinstall zlib1g-dev
    RUN wget -q https://github.com/openssl/openssl/releases/download/openssl-3.0.8/openssl-3.0.8.tar.gz
    RUN tar xvf openssl-3.0.8.tar.gz
    WORKDIR openssl-3.0.8
    RUN ./config -d --prefix=/usr/local/openssl-3.0.8 --openssldir=/usr/local/openssl-3.0.8
    RUN make -j && make install
    ENV OPENSSL_ROOT_DIR=/usr/local/openssl-3.0.8/
    ENV LD_LIBRARY_PATH=\$OPENSSL_ROOT_DIR/lib64:\$LD_LIBRARY_PATH

    # Install newer gdb
    RUN apt remove -y gdb
    RUN apt install -y build-essential texinfo bison flex \
                       libgmp-dev libexpat1-dev libmpfr-dev \
                       libipt-dev pkg-config babeltrace python
    WORKDIR /
    RUN wget -q https://ftp.gnu.org/gnu/gdb/gdb-11.2.tar.xz
    RUN tar xvf gdb-11.2.tar.xz
    WORKDIR gdb-11.2
    RUN ./configure
    RUN make -j20
    RUN make install

    RUN apt update -y && apt install -y valgrind

    ENV HOME=/build
    RUN groupadd --gid $(id -g) $(id -u -n)
    RUN useradd -s /bin/bash --uid $(id -u) --gid $(id -g) -m $(id -u -n) -G pcap -d ${HOME}
    RUN echo $(id -u -n) ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$(id -u -n) && chmod 0440 /etc/sudoers.d/$(id -u -n)
    USER $(id -u -n):$(id -g -n)

    ENV PATH=/opt/llvm/bin:\$PATH
    ENV LD_LIBRARY_PATH=/opt/llvm/lib:\$LD_LIBRARY_PATH

    VOLUME /build
    VOLUME /source

    ENTRYPOINT /entrypoint.sh
EOF

docker build --pull --iidfile "${TMP_DIR}/iid" "${TMP_DIR}"

mkdir -p "${ENVOY_OPENSSL_DIR}/build-volume"

docker run --rm \
           --tty \
           --interactive \
           --name "$(pwd | sed 's|/|-|g;s|^-||g')" \
           --network=host \
           --env BAZEL_REMOTE_CACHE \
           --env BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER \
           --volume="${ENVOY_OPENSSL_DIR}/build-volume:/build" \
           --cap-add=SYS_PTRACE \
           --security-opt seccomp=unconfined \
           --volume="${ENVOY_OPENSSL_DIR}:/source" \
           --volume="${HOME}:${HOME}" \
           --workdir=/source \
           $(cat "${TMP_DIR}/iid")


# bazel build @bssl-compat//:bssl-compat
# bazel build @envoy//:envoy
# cd envoy && bazel build :envoy
