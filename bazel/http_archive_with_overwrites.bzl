load("@bazel_tools//tools/build_defs/repo:utils.bzl", "patch")

def _http_archive_with_overwrites_impl(ctx):
    ctx.download_and_extract(
        url = ctx.attr.url,
        sha256 = ctx.attr.sha256,
        stripPrefix = ctx.attr.strip_prefix
    )
    patch(ctx)
    for f in ctx.attr.overwrites:
        ctx.file(Label(f).name, content = ctx.read(f),)

http_archive_with_overwrites = repository_rule(
    implementation = _http_archive_with_overwrites_impl,
    attrs = {
        "url": attr.string(),
        "sha256": attr.string(),
        "strip_prefix": attr.string(),
        "patches": attr.label_list(),
        "patch_args": attr.string_list(default = ["-p0"]),
        "overwrites": attr.label_list(),
    },
)
