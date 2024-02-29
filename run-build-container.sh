#!/bin/bash

set -euo pipefail

ENVOY_OPENSSL_DIR="$(cd "$(dirname "$0")" && pwd)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

DOCKER_IMAGE=$(sed -n 's/^build:docker-sandbox --experimental_docker_image=//p' "${ENVOY_OPENSSL_DIR}/envoy/.bazelrc")
if [[ -z "${DOCKER_IMAGE}" ]]; then
	echo "Failed to determine builder docker image"
	exit 1
fi


cat << 'EOF' > "${TMP_DIR}/entrypoint.sh"
    #!/bin/bash -e

    sudo chown -R "$(id -u):$(id -g)" $HOME
    export BAZELRC_FILE=$HOME/.bazelrc

    /source/envoy/bazel/setup_clang.sh /opt/llvm # Writes to $BAZELRC_FILE

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

    RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
    RUN sed -i "s|^deb.*kitware.*$|deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu focal InRelease|g" /etc/apt/sources.list
    RUN apt update -y
    RUN apt install -y vim
    RUN apt install -y gawk

    ADD https://go.dev/dl/go1.19.11.linux-amd64.tar.gz /tmp
    RUN tar -C /usr/local -xzf /tmp/go1.19.11.linux-amd64.tar.gz && rm /tmp/go1.19.11.linux-amd64.tar.gz
    ENV PATH=/usr/local/go/bin:\$PATH

    ENV HOME=/build
    RUN groupadd --gid $(id -g) $(id -u -n)
    RUN useradd -s /bin/bash --uid $(id -u) --gid $(id -g) -m $(id -u -n) -G pcap -d ${HOME}
    RUN echo $(id -u -n) ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$(id -u -n) && chmod 0440 /etc/sudoers.d/$(id -u -n)
    USER $(id -u -n):$(id -g -n)

    ENV PATH=/opt/llvm/bin:\$PATH
    ENV LD_LIBRARY_PATH=/opt/llvm/lib:\$LD_LIBRARY_PATH

    VOLUME /build
    VOLUME /source

    ADD --chmod=755 entrypoint.sh /entrypoint.sh
    ENTRYPOINT /entrypoint.sh
EOF

DOCKER_BUILDKIT=1 docker build --pull --iidfile "${TMP_DIR}/iid" "${TMP_DIR}"

mkdir -p "${ENVOY_OPENSSL_DIR}/build-volume"

docker run --rm \
           --tty \
           --interactive \
           --network=host \
           --env BAZEL_REMOTE_CACHE \
           --env BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER \
           --volume="${ENVOY_OPENSSL_DIR}/build-volume:/build" \
           --volume="${ENVOY_OPENSSL_DIR}:/source" \
           --volume="${HOME}:${HOME}" \
           --workdir=/source \
           $(cat "${TMP_DIR}/iid")


# bazel build @bssl-compat//:bssl-compat
# bazel build @envoy//:envoy
# cd envoy && bazel build :envoy
