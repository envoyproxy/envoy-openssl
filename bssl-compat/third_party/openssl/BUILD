# This BUILD file describes the system-installed OpenSSL library.
# It contains no sources, only the necessary settings for other targets to use it.
cc_library(
    name = "openssl",
    # This makes the headers in /usr/include available to any target
    # that depends on this one.
    includes = [
        "/usr/include",
    ],
    # These are the flags passed to the linker.
    linkopts = [
        # Tells the linker to search for libraries in this specific directory.
        "-L/usr/lib/x86_64-linux-gnu",
        # Tells the linker to link against libssl.so (-lssl)
        "-lssl",
        # and libcrypto.so (-lcrypto).
        "-lcrypto",
    ],
    # Make this target visible to your entire project.
    visibility = ["//visibility:public"],
)
