#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-func-decl OBJ_txt2obj \
  --uncomment-macro-redef 'OBJ_R_[[:alnum:]_]*'
