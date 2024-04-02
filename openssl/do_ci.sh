#!/bin/bash

set -x
set -eo pipefail

cd "$(dirname "$0")/.."

# Pick up the ENVOY_OPENSSL_ prefixed environment variables that were set by the
# openssl/run_envoy_docker.sh script, and ensure that they get added to the
# environment appropriately for building and testing envoy-openssl.
echo "test --test_env=LD_LIBRARY_PATH=${ENVOY_OPENSSL_LD_LIBRARY_PATH}:${LD_LIBRARY_PATH}" > openssl.bazelrc
echo "test --test_env=OPENSSL_CONF=$(pwd)/bssl-compat/source/test/openssl.cnf" >> openssl.bazelrc
export PATH="${ENVOY_OPENSSL_PATH}:${PATH}"

# Hand off to the upstream do_ci.sh script
exec ./ci/do_ci.sh "$@"