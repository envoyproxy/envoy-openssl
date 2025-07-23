load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])  # Apache 2

filegroup(
    name = "all",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)

# Set out_headers_only=True to stop executables linking against the OpenSSL shared libraries.
# This is required because we want executables to link against the bssl-compat library instead.
# The bssl-compat library is a static library that provides a compatibility layer for BoringSSL,
# by dynamically loading the OpenSSL shared libraries at run time.
#
# We do still list the OpenSSL shared libraries in out_shared_libs, so that they are made available
# in the sandbox of dependant targets, so bssl-compat can dynamically load them at run time.
configure_make(
    name = "openssl",
    lib_source = ":all",
    configure_in_place = True,
    configure_command = "Configure",
    targets = ["build_sw", "install_sw"],
    args = ["-j"],
    out_headers_only = True,
    out_include_dir = "include",
    out_lib_dir = "lib64",
    out_shared_libs = ["libssl.so.3", "libcrypto.so.3"],
    visibility = ["//visibility:public"],
)
