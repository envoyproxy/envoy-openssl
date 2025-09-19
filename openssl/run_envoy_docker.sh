#!/bin/bash

set -euo pipefail

# Change to the top dir
cd "$(dirname "$0")/.."

# Tell the upstream run_envoy_docker.sh script to use our builder image
export ENVOY_BUILD_IMAGE=$(grep ENVOY_BUILD_IMAGE .github/workflows/envoy-openssl.yml | awk '{print $2}')
# Hand off to the upstream run_envoy_docker.sh script
exec ./ci/run_envoy_docker.sh "$@"
