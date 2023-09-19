#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl ECDSA_sign \
  --uncomment-func-decl ECDSA_size \
  --uncomment-func-decl ECDSA_SIG_new \
  --uncomment-func-decl ECDSA_SIG_free \
  --uncomment-struct ecdsa_sig_st \
  --uncomment-macro-redef 'ECDSA_R_[[:alnum:]_]*' \
  --uncomment-regex 'BORINGSSL_MAKE_DELETER(ECDSA_SIG,'
