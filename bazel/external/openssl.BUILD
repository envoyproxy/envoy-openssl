load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
#load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library")

licenses(["notice"])  # Apache 2

filegroup(
    name = "all",
    srcs = glob(["**"]),
)

configure_make(
    name = "openssl",
    lib_source = ":all",
    lib_name = "openssl",
    configure_in_place = True,
    configure_command = "Configure",
    targets = ["build_sw", "install_sw"],
    args = ["-j"],
    out_lib_dir = "lib64",
    #out_static_libs = ["libssl.a", "libcrypto.a"],
    out_shared_libs = ["libssl.so.3", "libcrypto.so.3"],
    out_include_dir = "include",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libs",
    deps = [":openssl"],
    visibility = ["//visibility:public"],
    srcs = [":openssl"],
    linkstatic = True,
)

# envoy_cc_library(
#     name = "libs",
#     deps = [":openssl"],
#     repository = "@envoy",
#     rbe_pool = "6gig",
#     visibility = ["//visibility:public"],
#     srcs = [":openssl"],
#     data = [":openssl"],
#     alwayslink = True,
# )

# envoy_cc_library(
#     name = "crypto",
#     deps = [":openssl"],
#     repository = "@envoy",
#     rbe_pool = "6gig",
#     visibility = ["//visibility:public"],
#     srcs = [":openssl"],
# )
