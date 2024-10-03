#!/bin/bash

set -euo pipefail

uncomment.sh "$1" --comment \
  --uncomment-regex '#include' \
  --comment-regex '#include "../fipsmodule' \
  --uncomment-regex 'static\s*const\s*.*\<kPlaintext\[\]\s*=\s*' \
  --uncomment-regex 'static\s*const\s*.*\<kPlaintextLen\s*=\s*' \
  --uncomment-struct RSAEncryptParam \
  --uncomment-regex 'class\s*RSAEncryptTest\s*:' \
  --uncomment-gtest-func RSAEncryptTest TestKey \
  --uncomment-regex-range 'INSTANTIATE_TEST_SUITE_P(All, RSAEncryptTest' '.*);$' \
  --uncomment-gtest-func RSATest TestDecrypt \
  --uncomment-gtest-func RSATest OnlyDGiven \
  --uncomment-gtest-func RSATest GenerateSmallKey \
  --uncomment-gtest-func RSATest DecryptPublic \

for VAR in kKey1 kFIPSPublicKey kOAEPCiphertext1 kKey2 kOAEPCiphertext2 kKey3 kOAEPCiphertext3 kTwoPrimeKey kTwoPrimeEncryptedMessage; do
  uncomment.sh "$1" --uncomment-regex-range 'static\s*const\s*.*\<'$VAR'\[\]\s*=' '[^;]*;\s*$'
done
