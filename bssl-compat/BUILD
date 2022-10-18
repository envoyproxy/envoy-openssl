load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

licenses(["notice"])  # Apache 2

configure_make(
    name = "openssl",
    lib_source = "@openssl//:srcs",
    configure_command = "config",
    out_shared_libs = ["libcrypto.so", "libssl.so"],
    visibility = ["//visibility:public"],
)

cmake(
    name = "bssl-compat",
    lib_source = ":srcs",
    out_shared_libs = ["libbssl-compat.so"],
    out_static_libs = [],
    visibility = ["//visibility:public"],
    deps = [":openssl"],
)

alias(
    name = "ssl",
    actual = ":bssl-compat",
    visibility = ["//visibility:public"],
)
