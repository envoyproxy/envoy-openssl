#!/bin/bash

SUBSTITUTIONS+=('RSA_R_[a-zA-Z0-9_]*')
SUBSTITUTIONS+=('RSA_[a-zA-Z0-9_]*_PADDING')

EXPRE='s|^//[ \t]#[ \t]*define[ \t]*[^a-zA-Z0-9_]\('
EXPOST='\)[^a-zA-Z0-9_].*$|#ifdef ossl_\1\n#define \1 ossl_\1\n#endif|'

for SUBSTITUTION in "${SUBSTITUTIONS[@]}"
do
	sed -i -e "${EXPRE}${SUBSTITUTION}${EXPOST}" "$1"
done
