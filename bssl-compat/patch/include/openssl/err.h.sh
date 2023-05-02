#!/bin/bash

set -e

BSSL_COMPAT_DIR="$(cd "$(dirname "$0")/../../.."; pwd)"

sed -i -e 's|^// \([ \t]*\)\(ERR_LIB_[a-zA-Z0-9_]*\)[^a-zA-Z0-9_].*$|#ifdef ossl_\2\n\1\2 = ossl_\2,\n#endif|g' \
       -e 's|^// \(#[ \t]*define[ \t]*\)ERR_R_\([a-zA-Z0-9_]*\)_LIB[^a-zA-Z0-9_].*$|#ifdef ossl_ERR_R_\2_LIB\n\1ERR_R_\2_LIB ossl_ERR_R_\2_LIB\n#endif|g' \
       -e 's|^// \(#[ \t]*define[ \t]*\)\(ERR_R_[a-zA-Z0-9_]*\)[^a-zA-Z0-9_].*$|#ifdef ossl_\2\n\1\2 ossl_\2\n#endif|g' \
       -e 's|^// \(#[ \t]*define[ \t]*\)\(ERR_NUM_ERRORS\)[^a-zA-Z0-9_].*$|#ifdef ossl_\2\n\1\2 ossl_\2\n#endif|g' \
      "$1"
