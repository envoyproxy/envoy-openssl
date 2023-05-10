#!/bin/bash

SUBSTITUTIONS+=('SSL_ERROR_[a-zA-Z0-9_]*')
SUBSTITUTIONS+=('SSL_MODE_[a-zA-Z0-9_]*')
SUBSTITUTIONS+=('SSL_AD_[a-zA-Z0-9_]*')
SUBSTITUTIONS+=('DTLS1_VERSION_MAJOR')
SUBSTITUTIONS+=('SSL3_VERSION_MAJOR')
SUBSTITUTIONS+=('SSL3_VERSION')
SUBSTITUTIONS+=('TLS1_VERSION')
SUBSTITUTIONS+=('TLS1_1_VERSION')
SUBSTITUTIONS+=('TLS1_2_VERSION')
SUBSTITUTIONS+=('TLS1_3_VERSION')
SUBSTITUTIONS+=('DTLS1_VERSION')
SUBSTITUTIONS+=('DTLS1_2_VERSION')

EXPRE='s|^//[ \t]#[ \t]*define[ \t]*[^a-zA-Z0-9_]\('
EXPOST='\)[^a-zA-Z0-9_].*$|#ifdef ossl_\1\n#define \1 ossl_\1\n#endif|'

for SUBSTITUTION in "${SUBSTITUTIONS[@]}"
do
	sed -i -e "${EXPRE}${SUBSTITUTION}${EXPOST}" "$1"
done

sed -i -e 's|^// \(#[ \t]*define[ \t]*\)\(SSL_R_[a-zA-Z0-9_]*\)[^a-zA-Z0-9_].*$|#ifdef ossl_\2\n\1\2 ossl_\2\n#endif|g' "$1"

