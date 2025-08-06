cc_binary(
    name = "prefixer",
    srcs = ["prefixer.cpp"],
    copts = [
        "-DLLVM_LIBRARY_DIR=\\\"/opt/llvm/lib/\\\"",
        "-DLLVM_VERSION_STRING=\"14.0.0\"",
        "-fno-rtti",
    ],
    linkopts = [
      "-lclang-cpp",
    ],
    includes = [
        "@clang//include",   # Reference the include directory from /opt/llvm
    ],
    deps = [
        "@clang//:clang_lib",
    ],
    visibility = ["//visibility:public"],
)
