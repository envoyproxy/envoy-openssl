workspace(name = "envoy_openssl")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_foreign_cc",
    sha256 = "ce3121834693d76308f50fa62c548c2710f900d807beb11d97c25739b6995f58",
    strip_prefix = "rules_foreign_cc-a7f9e8b38cc2c8a7c66862dd6a4c8848e9829a02",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/a7f9e8b38cc2c8a7c66862dd6a4c8848e9829a02.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies(register_default_tools = False, register_built_tools = False)

local_repository(
    name = "bssl-compat",
    path = "bssl-compat",
)

# NOTE: Whenever the version of envoy is changed here, the files under the top
# level envoy directory must also be re-copied from the new envoy version.
load("//:bazel/http_archive_with_overwrites.bzl", "http_archive_with_overwrites")
http_archive_with_overwrites(
    name = "envoy",
    url = "https://github.com/envoyproxy/envoy/archive/refs/tags/v1.26.6.zip",
    sha256 = "031f7ba8a99b4b6d1a7098698c749015dca48308281bca0e0683271934e95c20",
    strip_prefix = "envoy-1.26.6",
    patch_args = [ "-p1" ],
    patches = [
        "//patch/envoy:bazel/repositories_extra.bzl.patch",
        "//patch/envoy:bazel/repositories.bzl.patch",
        "//patch/envoy:source/common/quic/BUILD.patch",
        "//patch/envoy:source/extensions/extensions_build_config.bzl.patch",
        "//patch/envoy:source/extensions/transport_sockets/tls/io_handle_bio.cc.patch",
        "//patch/envoy:source/extensions/transport_sockets/tls/ocsp/asn1_utility.cc.patch",
        "//patch/envoy:source/extensions/transport_sockets/tls/utility.cc.patch",
    ],
    overwrites = [
        "//patch/envoy:source/extensions/transport_sockets/tls/context_impl.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/context_impl.h",
        "//patch/envoy:source/extensions/transport_sockets/tls/ssl_handshaker.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/ssl_handshaker.h",
        "//patch/envoy:source/extensions/transport_sockets/tls/ssl_socket.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/ssl_socket.h",
        "//patch/envoy:source/extensions/transport_sockets/tls/context_config_impl.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/cert_validator.h",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/default_validator.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/default_validator.h",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/utility.h",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/utility.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/san_matcher.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/spiffe/spiffe_validator.cc",
        "//patch/envoy:source/extensions/transport_sockets/tls/cert_validator/spiffe/spiffe_validator.h",
        "//patch/envoy:source/extensions/filters/listener/tls_inspector/tls_inspector.h",
        "//patch/envoy:source/extensions/filters/listener/tls_inspector/tls_inspector.cc",
    ],
    repo_mapping = {
        "@boringssl": "@bssl-compat",
    },
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()
