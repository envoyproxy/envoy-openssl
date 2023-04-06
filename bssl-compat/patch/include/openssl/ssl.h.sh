#!/bin/bash

#
# Redefine BoringSSL's SSL_ERROR_* values to have the corresponding
# OpenSSL values. If OpenSSL doesn't have an equivalent value then
# remove the BoringSSL definition by commenting it out.
#

set -e # stop on error
#set -x # echo commands

BSSL_HDR="$(readlink -e "$1")"
OSSL_HDR="$(readlink -e "$(dirname "$BSSL_HDR")/../ossl/openssl/$(basename "$BSSL_HDR")")"

for SSL_ERROR in $(grep '^#define[ \t]*SSL_ERROR[A-Z_]*' "$BSSL_HDR" | sed -e 's/^#define[ \t]*//g' -e 's/ .*$//g')
do
	if grep -q "ossl_$SSL_ERROR" $OSSL_HDR
	then
		sed -i "s/#define[ \t]*$SSL_ERROR[ \t].*$/#define $SSL_ERROR ossl_$SSL_ERROR/g" $BSSL_HDR
	else
		sed -i "s/#define[ \t]*$SSL_ERROR[ \t].*$/\/\/#define $SSL_ERROR/g" $BSSL_HDR
	fi
done
