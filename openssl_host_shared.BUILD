licenses(["notice"])  # Apache 2

cc_library(
    name = "host-ssl-1-1",
    srcs = [
        "libssl.so.1.1",
        "libcrypto.so.1.1",
    ],
    visibility = ["//visibility:public"],
    linkstatic=False,
)

alias(
    name = "ssl",
    actual = "host-ssl-1-1",
    visibility = ["//visibility:public"],
)
