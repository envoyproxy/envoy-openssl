load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])  # Apache 2

filegroup(
    name = "all",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)

configure_make(
    name = "openssl",
    lib_source = ":all",
    configure_in_place = True,
    configure_command = "Configure",
    targets = ["build_sw", "install_sw"],
    args = ["-j"],
    out_lib_dir = "lib64",
    out_static_libs = ["libssl.a", "libcrypto.a"],
    out_shared_libs = ["libssl.so.3", "libssl.so", "libcrypto.so.3", "libcrypto.so"],
    out_include_dir = "include",
)

cc_library(
    name = "ssl",
    deps = [":openssl"],
    includes = ["include"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "crypto",
    deps = [":openssl"],
    visibility = ["//visibility:public"],
)
