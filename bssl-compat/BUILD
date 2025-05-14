load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

licenses(["notice"])  # Apache 2

genrule(
    name = "openssl_root_dir",
    srcs = ["@openssl//:openssl"],
    outs = ["openssl_root_dir.txt"],
    cmd = """
        set -e
        OPENSSL_FILE=$$(find $(locations @openssl//:openssl) -name libssl.so.3 | head -n1)
        OPENSSL_DIR=$$(dirname "$$OPENSSL_FILE")
        EXEC_ROOT=$$(pwd | sed 's#/bazel-out/.*##')
        echo $${EXEC_ROOT}/$${OPENSSL_DIR%/lib64} > $@
    """,
)

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
    data = ["@openssl//:openssl", ":openssl_root_dir"],
    env = {
        "OPENSSL_ROOT_FILE": "$(location :openssl_root_dir)",
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
