"""Bazel macros for bssl-compat library."""

def _bssl_header_impl(name, src_file, dst_file):
    """Generate a genrule for processing one BoringSSL header.

    Args:
        name: Unique name for this genrule
        src_file: Source path relative to third_party/boringssl/src/ (e.g., "include/openssl/aes.h")
        dst_file: Destination path (e.g., "include/openssl/aes.h")
    """
    # Tools that are always needed
    tools = [
        "//tools:uncomment.sh",
    ]

    # Source file from BoringSSL
    srcs = ["third_party/boringssl/src/" + src_file]

    # Optional patch script
    patch_script = "patch/" + dst_file + ".sh"

    # Optional patch file
    patch_file = "patch/" + dst_file + ".patch"

    native.genrule(
        name = name,
        srcs = srcs + native.glob([patch_script, patch_file]),
        outs = [dst_file],
        cmd = """
            # Set up paths - all paths need to be relative to bssl-compat package
            SRC_FILE="$(location third_party/boringssl/src/{src_file})"
            DST_FILE="$(location {dst_file})"
            # Patch files are in the package, so use relative paths from execroot
            PATCH_SCRIPT="external/bssl-compat/patch/{dst_file}.sh"
            PATCH_FILE="external/bssl-compat/patch/{dst_file}.patch"

            # Create output directory
            mkdir -p "$$(dirname $$DST_FILE)"

            # Create temporary directory
            TMP_DIR="$$DST_FILE.tmp"
            mkdir -p "$$TMP_DIR"
            trap 'rm -rf $$TMP_DIR' EXIT

            # Copy source file to working file
            WORKING="$$TMP_DIR/working.h"
            cp "$$SRC_FILE" "$$WORKING"
            chmod +w "$$WORKING"

            # Apply patch file if it exists
            if [ -f "$$PATCH_FILE" ]; then
                patch -s -f "$$WORKING" "$$PATCH_FILE" -o "$$TMP_DIR/applied.patch.h"
                cp "$$TMP_DIR/applied.patch.h" "$$WORKING"
            fi

            # Apply patch script if it exists, otherwise comment out the whole file
            if [ -f "$$PATCH_SCRIPT" ]; then
                TOOLS_DIR="$$(dirname "$(location //tools:uncomment.sh)")"
                PATH="$$TOOLS_DIR:$$PATH" bash "$$PATCH_SCRIPT" "$$WORKING"
                cp "$$WORKING" "$$TMP_DIR/applied.script.h"
            else
                bash $(location //tools:uncomment.sh) "$$WORKING" --comment
            fi

            # Copy result to destination
            cp "$$WORKING" "$$DST_FILE"
        """.format(src_file = src_file, dst_file = dst_file),
        tools = tools,
        visibility = ["//visibility:private"],
    )

def bssl_headers(headers):
    """Process multiple BoringSSL headers.

    Args:
        headers: List of header paths (e.g., ["include/openssl/aes.h", "include/openssl/bio.h"])
    """
    # Generate individual header processing rules
    header_targets = []
    for h in headers:
        # Generate a unique name from the path
        name = "bssl_header_" + h.replace("/", "_").replace(".", "_")
        _bssl_header_impl(name, h, h)
        header_targets.append(":" + name)

    # Create a filegroup containing all processed headers
    native.filegroup(
        name = "bssl_processed_headers",
        srcs = header_targets,
        visibility = ["//visibility:public"],
    )

def bssl_sources(sources):
    """Process BoringSSL source files.

    Similar to bssl_headers, but for source files (.cc, .c) from BoringSSL
    that need to be processed with patches.

    Args:
        sources: List of source paths relative to "source/" directory
                 (e.g., ["crypto/mem.cc", "ssl/ssl_x509.cc"])
    """
    source_targets = []
    for src in sources:
        # Generate a unique name from the path
        name = "bssl_source_" + src.replace("/", "_").replace(".", "_")
        # src is relative to "source/", so the BoringSSL source is at third_party/boringssl/src/{src}
        src_file = src  # e.g., "crypto/mem.cc"
        dst_file = "source/" + src  # e.g., "source/crypto/mem.cc"
        _bssl_header_impl(name, src_file, dst_file)
        source_targets.append(":" + name)

    # Create a filegroup containing all processed source files
    native.filegroup(
        name = "bssl_processed_sources",
        srcs = source_targets,
        visibility = ["//visibility:public"],
    )

def bssl_mappings(functions):
    """Find or generate mapping functions for BoringSSL API.

    For each function name, this either:
    1. Uses an existing hand-written source/function.c or source/function.cc if it exists, OR
    2. Creates a genrule that searches BoringSSL headers for the function signature
       and generates a .c file with a forwarding function that calls ossl_<function>

    Args:
        functions: List of function names (e.g., ["BIO_new", "BIO_free", "SSL_new"])
    """
    function_targets = []
    for func in functions:
        name = "bssl_func_" + func

        # Check if hand-written implementation exists (.c or .cc)
        hand_written_c = native.glob(["source/" + func + ".c"])
        hand_written_cc = native.glob(["source/" + func + ".cc"])

        if hand_written_c or hand_written_cc:
            # Create an alias to the source file so it has a consistent target name
            native.filegroup(
                name = name,
                srcs = [hand_written_c[0] if hand_written_c else hand_written_cc[0]],
                visibility = ["//visibility:private"],
            )
        else:
            # Generate the function using generate.c.sh
            out = "source/" + func + ".c"
            native.genrule(
                name = name,
                srcs = native.glob(["third_party/boringssl/src/include/openssl/*.h"]),
                outs = [out],
                cmd = """
                    mkdir -p "$$(dirname $(location {out}))"

                    # Deduce the include directory from the first include file
                    FIRST_INCLUDE="$$(echo $(SRCS) | awk '{{print $$1}}')"
                    BORINGSSL_INCLUDE_DIR="$$(dirname "$$(dirname "$$FIRST_INCLUDE")")"

                    # Run generate.c.sh with the BoringSSL include directory
                    $(location //tools:generate.c.sh) "{func}" "$(location {out})" "$$BORINGSSL_INCLUDE_DIR"
                """.format(func = func, out = out),
                tools = [
                    "//tools:generate.c.sh",
                ],
                visibility = ["//visibility:private"],
            )
        function_targets.append(":" + name)

    # Create a filegroup containing all function implementations (both hand-written and generated)
    native.filegroup(
        name = "bssl_mapping_sources",
        srcs = function_targets,
        visibility = ["//visibility:public"],
    )
