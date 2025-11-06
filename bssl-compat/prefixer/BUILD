load("@rules_cc//cc:defs.bzl", "cc_binary")

licenses(["notice"])  # Apache 2

cc_binary(
    name = "prefixer",
    srcs = ["prefixer.cpp"],
    copts = ["-fno-rtti"], # Required by libclang-cpp
    deps = ["@llvm//:libclang-cpp"],
    visibility = ["//visibility:public"],
)
