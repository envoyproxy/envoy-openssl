load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "patch", "workspace_and_buildfile")

# Do not edit these values directly. To update the version
# of envoy to be used, please run the update-envoy.sh script.
ENVOY_ORG = "envoyproxy"
ENVOY_REPO = "envoy"
ENVOY_BRANCH = "v1.26.6"
ENVOY_COMMIT = "c2919e90b0e63ad78602122d6c2c3e2c0df1e0fc"
ENVOY_SHA256 = "358df10deb5de6f6a02fae4994d9269672ae8eb6d9cd66bdba349bef7843d14a"


def _bssl_compat_repository_impl(ctx):
    ctx.symlink(ctx.path(Label("//:bssl-compat/WORKSPACE")).dirname, "")

_bssl_compat_repository = repository_rule(
    implementation = _bssl_compat_repository_impl,
    local = True,
)


def _vendored_envoy_impl(ctx):
    ctx.symlink(ctx.path(Label("//:vendor/envoy/BUILD")).dirname, "")

_vendored_envoy = repository_rule(
    implementation = _vendored_envoy_impl,
    local = True,
)


def _downloaded_envoy_impl(ctx):
    ctx.download_and_extract(
        url = "https://github.com/" + ENVOY_ORG + "/" + ENVOY_REPO + "/archive/" + ENVOY_COMMIT + ".tar.gz",
        sha256 = ENVOY_SHA256,
        stripPrefix = ENVOY_REPO + "-" + ENVOY_COMMIT,
    )
    patch(ctx)
    for f in ctx.attr.overwrites:
        ctx.file(Label(f).name, content = ctx.read(f),)

_downloaded_envoy = repository_rule(
    implementation = _downloaded_envoy_impl,
    attrs = {
        "patches": attr.label_list(),
        "patch_args": attr.string_list(default = ["-p1"]),
        "overwrites": attr.label_list(),
    },
)


# Sets up the @bssl-compat and @envoy repositories, ensuring that
# the @envoy repository uses @bssl-compat instead of @boringssl
def envoy_openssl_repositories(download = False):
    _bssl_compat_repository(
        name = "bssl-compat",
    )

    if download:
        _downloaded_envoy(
            name = "envoy",
            patches = [
                "//patch/envoy:bazel/repositories_extra.bzl.patch",
                "//patch/envoy:bazel/repositories.bzl.patch",
                "//patch/envoy:source/common/quic/BUILD.patch",
                "//patch/envoy:source/extensions/extensions_build_config.bzl.patch",
                "//patch/envoy:source/extensions/transport_sockets/tls/io_handle_bio.cc.patch",
                "//patch/envoy:source/extensions/transport_sockets/tls/ocsp/asn1_utility.cc.patch",
                "//patch/envoy:source/extensions/transport_sockets/tls/utility.cc.patch",
                # These next patches are temporary, just to get the envoy exe
                # to link while the full set of correct patches are being developed.
                "//patch/envoy:source/extensions/transport_sockets/tls/context_impl.cc.patch",
                "//patch/envoy:source/extensions/transport_sockets/tls/context_impl.h.patch",
                "//patch/envoy:source/extensions/transport_sockets/tls/context_config_impl.cc.patch",
                "//patch/envoy:source/extensions/transport_sockets/tls/ssl_handshaker.cc.patch",
                "//patch/envoy:test/extensions/transport_sockets/tls/test_private_key_method_provider.cc.patch",
            ],
            overwrites = [
                # "//patch/envoy:source/extensions/transport_sockets/tls/context_impl.cc",
                # "//patch/envoy:source/extensions/transport_sockets/tls/context_impl.h",
            ],
            repo_mapping = { "@boringssl": "@bssl-compat" }
        )
    else:
        _vendored_envoy(
            name = "envoy",
            repo_mapping = { "@boringssl": "@bssl-compat" }
        )
