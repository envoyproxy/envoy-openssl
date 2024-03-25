#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --sed '/openssl\/x509\.h/a#include <ossl/openssl/x509v3.h>' \
  --uncomment-macro-redef 'GEN_[[:alnum:]_]*' \
  --sed '/typedef struct GENERAL_NAME_st {/itypedef struct ossl_GENERAL_NAME_st GENERAL_NAME;' \
  --uncomment-regex 'DEFINE_STACK_OF(GENERAL_NAME)' \
  --uncomment-typedef GENERAL_NAMES \
  --uncomment-regex 'DEFINE_STACK_OF(GENERAL_NAMES)' \
  --sed '/typedef struct GENERAL_SUBTREE_st {/itypedef ossl_GENERAL_SUBTREE GENERAL_SUBTREE;' \
  --uncomment-regex 'DEFINE_STACK_OF(GENERAL_SUBTREE)' \
  --uncomment-macro-redef 'EXFLAG_[[:alnum:]_]*' \
  --uncomment-macro-redef 'KU_[[:alnum:]_]*' \
  --uncomment-regex 'DECLARE_ASN1_FUNCTIONS_const(BASIC_CONSTRAINTS)' \
  --uncomment-regex 'DECLARE_ASN1_FUNCTIONS(GENERAL_NAME)' \
  --uncomment-regex 'DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)' \
  --uncomment-func-decl GENERAL_NAME_set0_value \
  --uncomment-regex 'DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)' \
  --uncomment-regex 'DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)' \
  --uncomment-func-decl X509_get_extension_flags \
  --uncomment-func-decl X509_get_key_usage \
  --uncomment-regex 'BORINGSSL_MAKE_DELETER(BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free)' \
  --uncomment-regex 'BORINGSSL_MAKE_DELETER(GENERAL_NAME, GENERAL_NAME_free)' \
  --uncomment-regex 'BORINGSSL_MAKE_DELETER(GENERAL_SUBTREE, GENERAL_SUBTREE_free)' \
  --uncomment-regex 'BORINGSSL_MAKE_DELETER(NAME_CONSTRAINTS, NAME_CONSTRAINTS_free)' \
  --uncomment-macro-redef 'X509V3_R_[[:alnum:]_]*' \
  --uncomment-macro-redef 'X509V3_ADD_[[:alnum:]_]*' \

