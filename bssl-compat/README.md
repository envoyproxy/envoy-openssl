# Summary

Compatibility layer for BoringSSL to OpenSSL.

This builds on the work of the original Maistra bssl_wrapper code.

# Building
Initialize and update git submodules:

```
git submodule init
git submodule update
```
Build library and tests with:

```sh
mkdir build
cd build
cmake ..
cmake --build .
```

# Structure

The overall goal of the `bssl-compat` library is to provide an implementation of the BoringSSL API, sufficient enough that Envoy can be built against it. To provide that implementation, the `bssl-compat` library makes use of OpenSSL. Given this, it's clear that most code in the library will have to include headers from BoringSSL, to provide the API, and from OpenSSL, to provided the implementation. However, since the two sets of headers look extremely similar, they clash horribly when included in the same compilation unit. This leads to the `prefixer` tool, which gets built and run quite early in the build.

The `prefixer` tool copies the stock OpenSSL headers into `bssl-compat/include/ossl/openssl/*.h` and then adds the `ossl_` prefix to the name of every type, function, macro, effectively scoping the whole API. Prefixing the OpenSSL headers like this, enables us to write mapping code that includes headers from both BoringSSL and OpenSSL in the same compilation unit.

Since all of the OpenSSL identifiers are prefixed, the two sets of headers can coexist without clashing. However, such code will not link because it uses the prefixed symbols when making OpenSSL calls. To satisfy the prefixed symbols, the `prefixer` tool also generates the implementations of the prefixed functions into `bssl-compat/source/ossl.c`.

These generated functions simply make a forward call onto the real (non-prefixed) OpenSSL function, via a function pointer, which is set up by the generated `ossl_init()` library constructor function. This function is marked with the `__attribute__ ((constructor))` attribute, which ensures that it is called early, when the `bssl-compat` library is loaded. It uses `dlopen()` to load OpenSSL's `libcrypto.so` and `libssl.so`, and then uses `dlsym()` to lookup the address of each function and store it's address into the appropriate member of the generated `ossl_functions` struct.

![bssl-compat-build](bssl-compat-build.jpg)
