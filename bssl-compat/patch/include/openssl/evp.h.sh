#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl EVP_PKEY_new \
  --uncomment-func-decl EVP_PKEY_free \
  --uncomment-func-decl EVP_PKEY_cmp \
  --uncomment-func-decl EVP_PKEY_id \
  --uncomment-func-decl EVP_PKEY_assign_RSA \
  --uncomment-func-decl EVP_PKEY_get0_RSA \
  --uncomment-func-decl EVP_PKEY_get1_RSA \
  --uncomment-func-decl EVP_PKEY_assign_EC_KEY \
  --uncomment-func-decl EVP_PKEY_get0_EC_KEY \
  --uncomment-func-decl EVP_PKEY_get1_EC_KEY \
  --uncomment-macro-redef 'EVP_PKEY_[A-Z0-9_]*' \
  --uncomment-func-decl EVP_parse_public_key \
  --uncomment-func-decl EVP_DigestVerifyInit \
  --uncomment-func-decl EVP_DigestVerify \
  --uncomment-regex 'BORINGSSL_MAKE_DELETER(EVP_PKEY,'

