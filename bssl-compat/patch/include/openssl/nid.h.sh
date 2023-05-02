#!/bin/bash

SUBSTITUTIONS+=('SN_[a-zA-Z0-9_]*')
SUBSTITUTIONS+=('LN_[a-zA-Z0-9_]*')
SUBSTITUTIONS+=('NID_[a-zA-Z0-9_]*')
SUBSTITUTIONS+=('OBJ_[a-zA-Z0-9_]*')

EXPRE='s|^#[ \t]*define[ \t]*[^a-zA-Z0-9_]\('
EXPOST='\)[^a-zA-Z0-9_].*$|#ifdef ossl_\1\n#define \1 ossl_\1\n#endif|'

for SUBSTITUTION in "${SUBSTITUTIONS[@]}"
do
	sed -i -e "${EXPRE}${SUBSTITUTION}${EXPOST}" "$1"
done

sed -i -e 's|^[ \t]*1L, .*$||g' -e 's|^[ \t]*"[^"]*"$||g' "$1"
