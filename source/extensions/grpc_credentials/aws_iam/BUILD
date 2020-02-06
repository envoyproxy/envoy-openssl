licenses(["notice"])  # Apache 2

# AWS IAM gRPC Credentials

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_package",
)

envoy_package()

envoy_cc_extension(
    name = "config",
    repository = "@envoy",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    external_deps = ["grpc"],
    security_posture = "data_plane_agnostic",
    status = "alpha",
    deps = [
        "@envoy//include/envoy/grpc:google_grpc_creds_interface",
        "@envoy//include/envoy/registry",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/config:utility_lib",
        "@envoy//source/common/grpc:google_grpc_creds_lib",
        "@envoy//source/common/http:message_lib",
        "@envoy//source/common/http:utility_lib",
        "//source/extensions/common/aws:credentials_provider_impl_lib",
        "//source/extensions/common/aws:region_provider_impl_lib",
        "//source/extensions/common/aws:signer_impl_lib",
        "//source/extensions/common/aws:utility_lib",
        "@envoy//source/extensions/grpc_credentials:well_known_names",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/grpc_credential/v3:pkg_cc_proto",
    ],
)
