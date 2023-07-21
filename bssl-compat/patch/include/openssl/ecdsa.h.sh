#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl ECDSA_sign \
  --uncomment-func-decl ECDSA_size \
  --uncomment-macro-redef 'ECDSA_R_[[:alnum:]_]*'
