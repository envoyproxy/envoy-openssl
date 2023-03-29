#!/bin/bash

#
# Since NIDs are not standardised, and do actually differ between OpenSSL and
# BoringSSL, we need to redefine BoringSSL's NIDs to have the OpenSSL values.
#

set -e

BSSL_HDR="$(readlink -e "$1")"
OSSL_HDR="$(readlink -e "$(dirname "$BSSL_HDR")/../ossl/openssl/obj_mac.h")"

for NID in $(grep '^#define[ \t]*NID_' "$BSSL_HDR" | sed 's/^#define[ \t]*//g' | awk '{print $1}')
do
	if grep -q "#define[ \t]*ossl_$NID[ \t]" "$OSSL_HDR"
	then
		sed -i "s/^#define[ \t]*$NID[ \t].*$/#define $NID ossl_$NID/g"   "$BSSL_HDR"
	else
		sed -i "s/^#define[ \t]*$NID[ \t].*$/#define $NID ERROR/g"   "$BSSL_HDR"
	fi
done
