licenses(["notice"])  # Apache 2

cc_library(
    name = "host-ssl-1-1",
    srcs = [
        "libcrypto.so.1.1",
        "libssl.so.1.1",
    ],
    linkstatic = False,
    visibility = ["//visibility:public"],
)

alias(
    name = "ssl",
    actual = "host-ssl-1-1",
    visibility = ["//visibility:public"],
)
