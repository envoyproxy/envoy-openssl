load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

licenses(["notice"])  # Apache 2

cmake(
    name = "bssl-compat-cmake",
    lib_source = ":srcs",
    out_shared_libs = [],
    out_static_libs = ["libbssl-compat.a"],
    includes = ["include"],
    generate_crosstool_file = False,

    cache_entries = {"CMAKE_BUILD_TYPE": "Bazel"},
    generate_args = ["-GNinja"],

    build_args = [ "-j" ],
    #deps = ["@openssl//:libs"],
    build_data = ["@openssl//:libs"],
    env = {
        "OPENSSL_ROOT_DIR": "/build/bazel_root/base/execroot/envoy/bazel-out/k8-fastbuild/bin/external/openssl/openssl",
        "LD_LIBRARY_PATH": "/build/bazel_root/base/execroot/envoy/bazel-out/k8-fastbuild/bin/external/openssl/openssl/lib64",
    },
)

filegroup(
    name = "bssl_includes",
    srcs = glob([":bssl-compat-cmake/include/**/*.h"]),
    visibility = ["//visibility:private"],
)

cc_library(
    name = "bssl-compat",
    #srcs = [":bssl-compat-cmake/lib/libbssl-compat.a"],
    #srcs = [":bssl-compat-cmake"],
    linkstatic = True,
    includes = [":bssl-compat-cmake/include"],
    hdrs = [":bssl_includes"],
    deps = [":bssl-compat-cmake"],
    data = ["@openssl//:libs"],
)

alias(
    name = "crypto",
    actual = ":bssl-compat",
    visibility = ["//visibility:public"],
)

alias(
    name = "ssl",
    actual = ":bssl-compat",
    visibility = ["//visibility:public"],
)
