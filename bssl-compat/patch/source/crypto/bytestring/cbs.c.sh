#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment \
  --uncomment-regex '\#include <' \
  --uncomment-func-impl CBS_init \
  --uncomment-func-impl CBS_len \
  --uncomment-func-impl cbs_get \
  --uncomment-func-impl CBS_skip \
  --uncomment-func-impl CBS_data \
  --uncomment-func-impl cbs_get_u \
  --uncomment-func-impl CBS_get_u8 \
  --uncomment-func-impl CBS_get_u16 \
  --uncomment-func-impl CBS_get_bytes \
  --uncomment-func-impl cbs_get_length_prefixed \
  --uncomment-func-impl CBS_get_u16_length_prefixed \
