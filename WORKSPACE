workspace(name = "envoy_openssl")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_foreign_cc",
    sha256 = "ce3121834693d76308f50fa62c548c2710f900d807beb11d97c25739b6995f58",
    strip_prefix = "rules_foreign_cc-a7f9e8b38cc2c8a7c66862dd6a4c8848e9829a02",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/a7f9e8b38cc2c8a7c66862dd6a4c8848e9829a02.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()

openssl_files = """\
filegroup(
    name = "srcs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
"""

http_archive(
    name = "openssl",
    build_file_content = openssl_files,
    sha256 = "fc513913724790510f53af07caa24eaf0eae3fc8cf476c17c113221b5868edac",
    strip_prefix = "openssl-OpenSSL_1_1_1r",
    urls = ["https://github.com/openssl/openssl/archive/OpenSSL_1_1_1r.tar.gz"],
)

local_repository(
    name = "bssl-compat",
    path = "bssl-compat",
)

local_repository(
    name = "envoy",
    path = "envoy",
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
