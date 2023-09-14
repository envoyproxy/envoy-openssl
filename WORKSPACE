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

local_repository(
    name = "envoy",
    path = "envoy",
    repo_mapping = {
        "@boringssl": "@bssl-compat",
    },
)

# http_archive(
#     name = "envoy",
#     url = "https://github.com/envoyproxy/envoy/archive/refs/tags/v1.26.3.zip",
#     strip_prefix = "envoy-1.26.3",
#     patches = [ "//:bazel/envoy.patch" ],
#     patch_args = [ "-p1" ],
#     repo_mapping = {
#         "@boringssl": "@bssl-compat",
#     },
# )

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
