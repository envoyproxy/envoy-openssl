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

# Usage



