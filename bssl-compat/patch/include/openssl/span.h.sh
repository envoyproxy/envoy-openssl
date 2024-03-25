#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment -h \
  --uncomment-regex 'template <typename [TC]>' \
  --uncomment-class-fwd Span \
  --uncomment-regex-range 'namespace internal {' '.\s\s..\snamespace\sinternal' \
  --uncomment-class Span \
  --uncomment-regex '.*Span<T>::npos' \
  --uncomment-func-impl MakeSpan \
  --uncomment-func-impl MakeSpan \
  --uncomment-func-impl MakeConstSpan \
  --uncomment-func-impl MakeConstSpan \
