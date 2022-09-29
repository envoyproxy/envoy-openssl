load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)

cmake(
    name = "bssl-compat",
    lib_source = ":srcs",
    out_shared_libs = ["libbssl-compat.so"],
    out_static_libs = [],
)
