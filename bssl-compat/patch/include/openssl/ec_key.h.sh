#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl EC_KEY_free \
  --uncomment-func-decl EC_KEY_get0_group \
  --uncomment-func-decl EC_KEY_parse_private_key \
  --uncomment-func-decl EC_KEY_new_by_curve_name \
  --uncomment-func-decl EC_KEY_set_public_key_affine_coordinates \
  --uncomment-regex 'BORINGSSL_MAKE_DELETER(EC_KEY'
