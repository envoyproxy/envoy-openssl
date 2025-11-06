load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])  # Apache 2

# libclang-cpp from llvm, used by the bssl-compat prefixer tool.
cc_library(
    name = "libclang-cpp",
    srcs = glob(["lib/libclang-cpp.*"]),
    hdrs = glob(["include/**/*"]),
    includes = ["include"],
    linkopts = ["-lstdc++"],
    visibility = ["//visibility:public"],
)

# The clang compiler built-in headers (stdef.h, limits.h etc)
filegroup(
    name = "clang-headers",
    srcs = glob(["lib/clang/*/include/**/*.h"]),
    visibility = ["//visibility:public"],
)