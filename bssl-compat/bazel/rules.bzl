"""Bazel macros for bssl-compat library."""

def _copy_bssl_file_impl(name, src_file, dst_file):
    """Generate a genrule for copying & patching one BoringSSL file.

    Args:
        name: Unique name for this genrule
        src_file: Source path relative to third_party/boringssl/ (e.g., "src/include/openssl/aes.h")
        dst_file: Destination path (e.g., "boringssl/src/include/openssl/aes.h")
    """
    native.genrule(
        name = name,
        srcs = [
            "third_party/boringssl/" + src_file
        ] + native.glob([
            "patch/" + dst_file + ".sh",
            "patch/" + dst_file + ".patch"
        ]),
        outs = [dst_file],
        cmd = """
            # Set up paths - all paths need to be relative to bssl-compat package
            SRC_FILE="$(location third_party/boringssl/{src_file})"
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
        tools = ["//tools:uncomment.sh"],
        visibility = ["//visibility:private"],
    )

def copy_bssl_files(groupname, destination, files):
    """Copy BoringSSL files into bssl-compat, applying patches.

    Args:
        groupname: The name of the resulting filegroup,
                   containing all the copied files
        destination: The directory to copy the files to
        files: List of source files relative to third_party/boringssl
                 (e.g., ["src/crypto/mem.cc", "src/ssl/ssl_x509.cc"])
    """
    targets = []
    for file in files:
        name = groupname + "_" + file.replace("/", "_").replace(".", "_")
        _copy_bssl_file_impl(
            name = name,
            src_file = file,
            dst_file = destination + "/" + file
        )
        targets.append(":" + name)
    # Create a filegroup containing all copied BoringSSL files
    native.filegroup(
        name = groupname,
        srcs = targets,
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
