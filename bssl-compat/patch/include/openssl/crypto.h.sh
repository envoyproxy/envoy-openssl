#!/bin/bash

sed -i -e 's|^// \(#[ \t]*define[ \t]*\)\(CRYPTO_R_[a-zA-Z0-9_]*\)[^a-zA-Z0-9_].*$|#ifdef ossl_\2\n\1\2 ossl_\2\n#endif|g' "$1"

