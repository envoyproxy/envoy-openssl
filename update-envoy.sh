#!/bin/bash

set -euo pipefail
set -x

SCRATCHDIR="$(mktemp -d)"
trap 'rm -rf -- "${SCRATCHDIR}" &> /dev/null' EXIT

ENVOY_ORG="${ENVOY_ORG:-envoyproxy}"
ENVOY_REPO="${ENVOY_REPO:-envoy}"
ENVOY_BRANCH="${ENVOY_BRANCH:-}"

WORKSPACE="$(cd "$(dirname "$0")" & pwd)"
VENDOR_DIR="${WORKSPACE}/vendor"
VENDOR_BAZELRC="${WORKSPACE}/vendor.bazelrc"
OUTPUT_BASE="${SCRATCHDIR}/output"

# If ${ENVOY_BRANCH} is blank then work out what branch
# of the envoy-openssl repository we are on, and use that.
if [[ -z "${ENVOY_BRANCH}" ]]; then
  ENVOY_BRANCH="$(cd "${WORKSPACE}" && git symbolic-ref --quiet --short HEAD)"
fi

# If ${ENVOY_BRANCH} has been specified by the caller, or worked out by us,
# then update the constants in bazel/envoy_openssl_repositories.bzl
if [[ "${ENVOY_BRANCH}" != "skip" ]]; then
  # Download the envoy branch
  cd "${SCRATCHDIR}"
  echo "Fetching ${ENVOY_ORG}/${ENVOY_REPO}[${ENVOY_BRANCH}]"
  git clone --depth=1 -b "${ENVOY_BRANCH}" "https://github.com/${ENVOY_ORG}/${ENVOY_REPO}.git"

  # Get the commit id
  cd "${ENVOY_REPO}"
  ENVOY_COMMIT=$(git rev-parse HEAD)

  # Get the SHA256
  cd "${SCRATCHDIR}"
  curl -sfLO "https://github.com/${ENVOY_ORG}/${ENVOY_REPO}/archive/${ENVOY_COMMIT}.tar.gz"
  ENVOY_SHA256=$(sha256sum "${ENVOY_COMMIT}.tar.gz" | awk '{print $1}')

  # Update the envoy org, repo, commit & sha256 valuse in envoy_openssl_repositories.bzl
  sed -i "s|^ENVOY_ORG = .*|ENVOY_ORG = \"${ENVOY_ORG}\"|" "${WORKSPACE}/bazel/envoy_openssl_repositories.bzl"
  sed -i "s|^ENVOY_REPO = .*|ENVOY_REPO = \"${ENVOY_REPO}\"|" "${WORKSPACE}/bazel/envoy_openssl_repositories.bzl"
  sed -i "s|^ENVOY_BRANCH = .*|ENVOY_BRANCH = \"${ENVOY_BRANCH}\"|" "${WORKSPACE}/bazel/envoy_openssl_repositories.bzl"
  sed -i "s|^ENVOY_COMMIT = .*|ENVOY_COMMIT = \"${ENVOY_COMMIT}\"|" "${WORKSPACE}/bazel/envoy_openssl_repositories.bzl"
  sed -i "s|^ENVOY_SHA256 = .*|ENVOY_SHA256 = \"${ENVOY_SHA256}\"|" "${WORKSPACE}/bazel/envoy_openssl_repositories.bzl"
fi


# Work out what bazel cache options to use
BAZEL_CACHE_FLAGS=""
if [[ -n ${BAZEL_REMOTE_CACHE} ]]; then
  BAZEL_CACHE_FLAGS="--remote_cache=${BAZEL_REMOTE_CACHE}"
  if [[ -n ${BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER} ]]; then
    BAZEL_CACHE_FLAGS+=" --experimental_remote_downloader=${BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER}"
  fi
elif [[ -n ${BAZEL_DISK_CACHE} ]]; then
  BAZEL_CACHE_FLAGS+="--disk_cache=${BAZEL_DISK_CACHE}"
fi

# Empty the vendor bazelrc file so bazel will always fetch envoy
: > "${VENDOR_BAZELRC}"

# Use build --nobuild, rather than fetch, because it honours configuration options
cd "${WORKSPACE}"
bazel --output_base="${OUTPUT_BASE}" build --nobuild ${BAZEL_CACHE_FLAGS} @envoy//:envoy

# Copy the fetched & patched envoy directory to the ${VENDOR_DIR}
rm -r "${VENDOR_DIR}/envoy"
cp -rL "${OUTPUT_BASE}/external/envoy" "${VENDOR_DIR}/envoy"

# Remove stuff that we don't need to vendor
find "${VENDOR_DIR}" -name .git -type d -print0 | xargs -0 -r rm -rf
find "${VENDOR_DIR}" -name .gitignore -type f -delete
find "${VENDOR_DIR}" -name __pycache__ -type d -print0 | xargs -0 -r rm -rf
find "${VENDOR_DIR}" -name '*.pyc' -delete

# Reintate the vendored envoy repository mapping
echo "build --override_repository=envoy=%workspace%/vendor/envoy" > "${VENDOR_BAZELRC}"


echo
echo "========================================"
echo "Done. Inspect the result with git status"
echo "========================================"
echo
