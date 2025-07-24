#!/bin/sh

set +x

echo "TED: \$0 = '$0'"
echo "TED: \$@ = '$@'"

echo "TED:"
echo "TED: readelf -d \"$1\" ...."
readelf -d "$1" | sed 's/^/TED: /g'

echo "TED:"
echo "TED: ldd \"$1\" ...."
ldd "$1" | sed 's/^/TED: /g'

ORIGIN="$(dirname "$(readlink -f "$1")")"

readelf -d "$1" | awk '/RUNPATH/ {match($0, /Library runpath: \[(.*)\]/, a); print a[1]}' | \
tr ':' '\n' | while IFS= read -r RUNPATH; do
    echo "TED:"
    echo "TED: RUNPATH    : $RUNPATH"
    ABSRUNPATH="$(readlink -f "$(echo "$RUNPATH" | sed "s|\$ORIGIN|$ORIGIN|g")")"
    if [ -d "${ABSRUNPATH}" ]; then
        echo "TED: ABSRUNPATH : $ABSRUNPATH"
        find "$ABSRUNPATH" -name "*.so*" | while IFS= read -r SOFILE; do
            echo "TED: SOFILE     : $SOFILE"
            ls -l "$SOFILE" | sed 's/^/TED:            :   /g'
            file "$SOFILE" | sed 's/^/TED:            :   /g'
            file --dereference "$SOFILE" | sed 's/^/TED:            :   /g'
            ldd "$SOFILE" | sed 's/^/TED:            :   /g'
        done
    else
        echo "TED: ABSRUNPATH not found: $ABSRUNPATH"
    fi
done


# Helper shell script for :corpus_from_config_impl genrule in BUILD.

# Set NORUNFILES so test/main doesn't fail when runfiles manifest is not found.
SHARDS=5
for INDEX in $(seq 0 $((SHARDS-1))) ; do
  if ! TEXT=$(NORUNFILES=1 GTEST_TOTAL_SHARDS=$SHARDS GTEST_SHARD_INDEX=$INDEX "$@" 2>&1); then
    echo "$TEXT"
    echo "Router test failed to pass: debug logs above"
    exit 1
  fi
done

set -e

# Verify at least one entry is actually generated
[ -e "${GENRULE_OUTPUT_DIR}"/generated_corpus_0 ]
