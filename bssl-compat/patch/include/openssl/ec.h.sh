#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl EC_GROUP_get0_order \
  --uncomment-func-decl EC_GROUP_get_curve_name \
  --uncomment-func-decl EC_GROUP_get_degree \
  --uncomment-macro-redef 'EC_R_[[:alnum:]_]*'
