#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
--uncomment-func-decl RSA_new \
--uncomment-func-decl RSA_free \
--uncomment-func-decl RSA_bits \
--uncomment-func-decl RSA_get0_key \
--uncomment-func-decl RSA_get0_factors \
--uncomment-func-decl RSA_get0_crt_params \
--uncomment-func-decl RSA_set0_key \
--uncomment-func-decl RSA_set0_factors \
--uncomment-func-decl RSA_set0_crt_params \
--uncomment-func-decl RSA_generate_key_ex \
--uncomment-func-decl RSA_encrypt \
--uncomment-func-decl RSA_decrypt \
--uncomment-func-decl RSA_sign \
--uncomment-func-decl RSA_verify \
--uncomment-func-decl RSA_size \
--uncomment-func-decl RSA_check_key \
--uncomment-func-decl RSA_add_pkcs1_prefix \
--uncomment-func-decl RSA_public_key_from_bytes \
--uncomment-func-decl RSA_private_key_from_bytes \
--uncomment-macro-redef 'RSA_R_[a-zA-Z0-9_]*' \
--uncomment-macro-redef 'RSA_[a-zA-Z0-9_]*_PADDING' \
--uncomment-macro-redef RSA_F4 \
--uncomment-regex 'BORINGSSL_MAKE_DELETER(RSA'
