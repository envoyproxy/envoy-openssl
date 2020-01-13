load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def openssl_repository():
    http_archive(
        name = "openssl",
        urls = ["https://github.com/openssl/openssl/archive/OpenSSL_1_1_1d.tar.gz"],
        sha256 = "23011a5cc78e53d0dc98dfa608c51e72bcd350aa57df74c5d5574ba4ffb62e74",
        build_file = "@//:openssl.BUILD",
        strip_prefix = "openssl-OpenSSL_1_1_1d",
    )

def openssl_shared_repository():
    native.new_local_repository(
        name = "openssl",
        path = "/usr/lib/x86_64-linux-gnu",
        build_file = "openssl_host_shared.BUILD"
    )
