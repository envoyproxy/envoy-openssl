licenses(["notice"])  # Apache 2

# L7 HTTP AWS request signing filter
# Public docs: docs/root/configuration/http_filters/aws_request_signing_filter.rst

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "aws_request_signing_filter_lib",
    repository = "@envoy",
    srcs = ["aws_request_signing_filter.cc"],
    hdrs = ["aws_request_signing_filter.h"],
    deps = [
        "@envoy//include/envoy/http:filter_interface",
        "//source/extensions/common/aws:credentials_provider_impl_lib",
        "//source/extensions/common/aws:signer_impl_lib",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy_api//envoy/extensions/filters/http/aws_request_signing/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    repository = "@envoy",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    security_posture = "requires_trusted_downstream_and_upstream",
    status = "alpha",
    deps = [
        ":aws_request_signing_filter_lib",
        "@envoy//include/envoy/registry",
        "//source/extensions/common/aws:credentials_provider_impl_lib",
        "//source/extensions/common/aws:signer_impl_lib",
        "@envoy//source/extensions/filters/http:well_known_names",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/aws_request_signing/v3:pkg_cc_proto",
    ],
)
