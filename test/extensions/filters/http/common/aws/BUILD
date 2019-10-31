licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_mock",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()

envoy_cc_mock(
    name = "aws_mocks",
    repository = "@envoy",
    srcs = ["mocks.cc"],
    hdrs = ["mocks.h"],
    deps = [
        "//source/extensions/filters/http/common/aws:credentials_provider_interface",
        "//source/extensions/filters/http/common/aws:signer_interface",
    ],
)

envoy_cc_test(
    name = "signer_impl_test",
    repository = "@envoy",
    srcs = ["signer_impl_test.cc"],
    deps = [
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/http:message_lib",
        "//source/extensions/filters/http/common/aws:signer_impl_lib",
        "//test/extensions/filters/http/common/aws:aws_mocks",
        "@envoy//test/test_common:simulated_time_system_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "utility_test",
    repository = "@envoy",
    srcs = ["utility_test.cc"],
    deps = [
        "//source/extensions/filters/http/common/aws:utility_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "region_provider_impl_test",
    repository = "@envoy",
    srcs = ["region_provider_impl_test.cc"],
    deps = [
        "//source/extensions/filters/http/common/aws:region_provider_impl_lib",
        "@envoy//test/test_common:environment_lib",
    ],
)

envoy_cc_test(
    name = "credentials_provider_impl_test",
    repository = "@envoy",
    srcs = ["credentials_provider_impl_test.cc"],
    deps = [
        "//source/extensions/filters/http/common/aws:credentials_provider_impl_lib",
        "//test/extensions/filters/http/common/aws:aws_mocks",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/event:event_mocks",
        "@envoy//test/test_common:environment_lib",
        "@envoy//test/test_common:simulated_time_system_lib",
    ],
)

envoy_cc_test(
    name = "credentials_provider_test",
    repository = "@envoy",
    srcs = ["credentials_provider_test.cc"],
    deps = [
        "//source/extensions/filters/http/common/aws:credentials_provider_interface",
    ],
)
