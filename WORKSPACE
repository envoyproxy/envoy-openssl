workspace(name = "envoy_openssl")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "openssl",
    build_file = "@//:openssl.BUILD",
    sha256 = "281e4f13142b53657bd154481e18195b2d477572fdffa8ed1065f73ef5a19777",
    strip_prefix = "openssl-OpenSSL_1_1_1g",
    urls = ["https://github.com/openssl/openssl/archive/OpenSSL_1_1_1g.tar.gz"],
)

new_local_repository(
    name = "openssl_shared",
    build_file = "openssl_host_shared.BUILD",
    path = "/usr/lib/x86_64-linux-gnu",
)

local_repository(
    name = "envoy_build_config",
    path = "envoy_build_config",
)

local_repository(
    name = "envoy",
    path = "envoy",
    repo_mapping = {
        "@boringssl": "@openssl",
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

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

#load("@envoy//bazel:repository_locations.bzl", "DEPENDENCY_REPOSITORIES")

#http_archive(
#    name = "com_github_google_jwt_verify_patched",
#    patch_args = ["-p1"],
#    patches = ["//:jwt_verify-make-compatible-with-openssl.patch"],
#    sha256 = DEPENDENCY_REPOSITORIES["com_github_google_jwt_verify"]["sha256"],
#    strip_prefix = DEPENDENCY_REPOSITORIES["com_github_google_jwt_verify"].get("strip_prefix", ""),
#    urls = DEPENDENCY_REPOSITORIES["com_github_google_jwt_verify"]["urls"],
#)
http_archive(
    name = "com_github_google_jwt_verify_patched",
    patch_args = ["-p1"],
    patches = ["//:jwt_verify-make-compatible-with-openssl.patch"],
    sha256 = "118f955620509f1634cbd918c63234d2048dce56b1815caf348d78e3c3dc899c",
    strip_prefix = "jwt_verify_lib-44291b2ee4c19631e5a0a0bf4f965436a9364ca7",
	urls = ["https://github.com/google/jwt_verify_lib/archive/44291b2ee4c19631e5a0a0bf4f965436a9364ca7.tar.gz"],
)

# TODO: Consider not using `bind`. See https://github.com/bazelbuild/bazel/issues/1952 for details.
bind(
    name = "jwt_verify_lib",
    actual = "@com_github_google_jwt_verify_patched//:jwt_verify_lib",
)
