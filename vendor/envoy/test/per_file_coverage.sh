#!/bin/bash

# directory:coverage_percent
# for existing directories with low coverage.
declare -a KNOWN_LOW_COVERAGE=(
"source/common:96.0"
"source/common/api:82.4"
"source/common/api/posix:81.3"
"source/common/common/posix:92.7"
"source/common/config:96.0"
"source/common/crypto:88.1"
"source/common/event:95.1" # Emulated edge events guards don't report LCOV
"source/common/filesystem/posix:96.5" # FileReadToEndNotReadable keeps failing
"source/common/http:96.3"
"source/common/http/http2:95.0"
"source/common/io:6.7"
"source/common/json:93.4"
"source/common/matcher:94.6"
"source/common/network:94.4" # Flaky, `activateFileEvents`, `startSecureTransport` and `ioctl`, listener_socket do not always report LCOV
"source/common/network/dns_resolver:91.6"  # A few lines of MacOS code not tested in linux scripts. Tested in MacOS scripts
"source/common/protobuf:96.3"
"source/common/quic:93.1"
"source/common/router:96.1"
"source/common/secret:95.0"
"source/common/signal:87.2" # Death tests don't report LCOV
"source/common/singleton:95.7"
"source/common/tcp:93.0"
"source/common/thread:0.0" # Death tests don't report LCOV
"source/common/tracing:97.1"
"source/common/upstream:96.4"
"source/common/watchdog:58.6" # Death tests don't report LCOV
"source/exe:94.5"
"source/extensions/access_loggers/wasm:93.5"
"source/extensions/clusters/common:91.5" # This can be increased again once `#24903` lands
"source/extensions/common:93.0" #flaky: be careful adjusting
"source/extensions/common/proxy_protocol:93.8" # Adjusted for security patch
"source/extensions/common/tap:94.2"
"source/extensions/common/wasm:87.5" # flaky: be careful adjusting
"source/extensions/common/wasm/ext:92.0"
"source/extensions/filters/common:96.5"
"source/extensions/filters/common/fault:94.5"
"source/extensions/filters/common/rbac:90.5"
"source/extensions/filters/http/cache:93.3"
"source/extensions/filters/http/grpc_json_transcoder:95.6"
"source/extensions/filters/http/ip_tagging:88.0"
"source/extensions/filters/http/kill_request:91.7" # Death tests don't report LCOV
"source/extensions/filters/http/wasm:1.9"
"source/extensions/filters/http/rate_limit_quota:94" # TODO(tyxia) WIP. Improve coverage as development continues
"source/extensions/filters/listener/original_dst:82.9"
"source/extensions/filters/listener/original_src:92.1"
"source/extensions/filters/network/common:96.1"
"source/extensions/filters/network/common/redis:96.4"
"source/extensions/filters/network/mongo_proxy:96.0"
"source/extensions/filters/network/sni_cluster:88.9"
"source/extensions/filters/network/thrift_proxy/router:96.5"
"source/extensions/filters/network/thrift_proxy/filters/payload_to_metadata:96.2"
"source/extensions/filters/network/wasm:76.9"
"source/extensions/http/cache/simple_http_cache:95.9"
"source/extensions/rate_limit_descriptors:95.5"
"source/extensions/rate_limit_descriptors/expr:95.5"
"source/extensions/stat_sinks/graphite_statsd:82.1"
"source/extensions/stat_sinks/statsd:84.6"
"source/extensions/tracers:95.8"
"source/extensions/tracers/common:73.8"
"source/extensions/tracers/common/ot:71.7"
"source/extensions/tracers/opencensus:93.2"
"source/extensions/tracers/zipkin:95.8"
"source/extensions/transport_sockets:95.6"
"source/extensions/transport_sockets/tls:94.8"
"source/extensions/transport_sockets/tls/cert_validator:95.1"
"source/extensions/transport_sockets/tls/private_key:88.9"
"source/extensions/wasm_runtime/wamr:0.0" # Not enabled in coverage build
"source/extensions/wasm_runtime/wasmtime:0.0" # Not enabled in coverage build
"source/extensions/wasm_runtime/wavm:0.0" # Not enabled in coverage build
"source/extensions/watchdog:83.3" # Death tests within extensions
"source/extensions/listener_managers/validation_listener_manager:69.6"
"source/extensions/watchdog/profile_action:83.3"
"source/server:93.3" # flaky: be careful adjusting. See https://github.com/envoyproxy/envoy/issues/15239
"source/server/admin:profiler-lib:83"
"source/extensions/load_balancing_policies/common:94" # Death tests don't report LCOV
"source/server/config_validation:83.8"
"source/extensions/health_checkers:95.5"
"source/extensions/health_checkers/http:93.8"
"source/extensions/health_checkers/grpc:92.0"
)

[[ -z "${SRCDIR}" ]] && SRCDIR="${PWD}"
COVERAGE_DIR="${SRCDIR}"/generated/coverage
COVERAGE_DATA="${COVERAGE_DIR}/coverage.dat"

FAILED=0
DEFAULT_COVERAGE_THRESHOLD=96.6
DIRECTORY_THRESHOLD=$DEFAULT_COVERAGE_THRESHOLD

# Unfortunately we have a bunch of preexisting directory with low coverage.
# Set their low bar as their current coverage level.
get_coverage_target() {
  DIRECTORY_THRESHOLD=$DEFAULT_COVERAGE_THRESHOLD
  for FILE_PERCENT in "${KNOWN_LOW_COVERAGE[@]}"
  do
    if [[ $FILE_PERCENT =~ $1: ]]; then
      DIRECTORY_THRESHOLD="${FILE_PERCENT//*:/}"
      return
    fi
  done
}

# Make sure that for each directory with code, coverage doesn't dip
# below the default coverage threshold.
SOURCES=$(find source/* -type d)
while read -r DIRECTORY
do
  get_coverage_target "$DIRECTORY"
  COVERAGE_VALUE=$(lcov -e "$COVERAGE_DATA"  "${DIRECTORY}/*" -o /dev/null | grep line |  cut -d ' ' -f 4)
  COVERAGE_VALUE=${COVERAGE_VALUE%?}
  # If the coverage number is 'n' (no data found) there is 0% coverage. This is
  # probably a directory without source code, so we skip checks.
  #
  # We could insist that we validate that 0% coverage directories are in a
  # documented list, but instead of adding busy-work for folks adding
  # non-source-containing directories, we trust reviewers to notice if there's
  # absolutely no tests for a full directory.
  if [[ $COVERAGE_VALUE =~ "n" ]]; then
    continue;
  fi;
  COVERAGE_FAILED=$(echo "${COVERAGE_VALUE}<${DIRECTORY_THRESHOLD}" | bc)
  if [[ "${COVERAGE_FAILED}" -eq 1 ]]; then
    echo "Code coverage for ${DIRECTORY} is lower than limit of ${DIRECTORY_THRESHOLD} (${COVERAGE_VALUE})"
    FAILED=1
  fi
  if [[ -n ${VERBOSE} && ${COVERAGE_VALUE} > ${DIRECTORY_THRESHOLD} ]]; then
    if [[ ${DIRECTORY_THRESHOLD} < $DEFAULT_COVERAGE_THRESHOLD ]]; then
      echo "Code coverage for ${DIRECTORY} is now ${COVERAGE_VALUE} (previously ${DIRECTORY_THRESHOLD})"
    fi
  fi

done <<< "$SOURCES"

exit $FAILED
