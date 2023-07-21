#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl EC_KEY_free \
  --uncomment-func-decl EC_KEY_get0_group \
  --uncomment-func-decl EC_KEY_parse_private_key
