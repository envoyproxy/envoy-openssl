#!/bin/bash

set -e # Quit on error
# set -x # Echo commands

BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

function status {
  echo -e "${BLUE}$1${NC}"
}

function warn {
  echo -e "${YELLOW}$1${NC}"
}

function error {
  echo -e "${RED}$1${NC}"
  exit 1
}

#
# Get command line args
#
UNCOMMENT_SCRIPT="${1?"UNCOMMENT_SCRIPT not specified"}"
SRC_FILE="${2?"SRC_FILE not specified"}" # e.g. crypto/err/internal.h
DST_FILE="${3?"DST_FILE not specified"}" # e.g. source/crypto/err/internal.h
DST_DIR="${4?"DST_DIR not specified"}"
PATCH_DIR="${5?"PATCH_DIR not specified"}"


#
# Check/Ensure the inputs and outputs exist
#
[ -d "${PATCH_DIR}" ] || error "PATCH_DIR $PATCH_DIR does not exist"
[ -f "${UNCOMMENT_SCRIPT}" ] || error "UNCOMMENT_SCRIPT $UNCOMMENT_SCRIPT does not exist"
[ -f "${SRC_FILE}" ] || error "SRC_FILE $SRC_FILE does not exist"
mkdir -p "$(dirname "$DST_DIR/$DST_FILE")"
mkdir -p "$(dirname "$DST_FILE")"


#
# Apply script file from $PATCH_DIR
# =================================
#
PATCH_SCRIPT="$PATCH_DIR/$DST_FILE.sh"
GEN_APPLIED_SCRIPT="$DST_FILE.1.applied.script"
cp "$SRC_FILE" "$GEN_APPLIED_SCRIPT"
if [ -f "$PATCH_SCRIPT" ]; then
    PATH="$(dirname "$0"):$PATH" "$PATCH_SCRIPT" "$GEN_APPLIED_SCRIPT"
else # Comment out the whole file contents
    $UNCOMMENT_SCRIPT "$GEN_APPLIED_SCRIPT" --comment
fi


#
# Apply patch file from $PATCH_DIR
# ================================
#
PATCH_FILE="$PATCH_DIR/$DST_FILE.patch"
GEN_APPLIED_PATCH="$DST_FILE.2.applied.patch"
if [ -f "$PATCH_FILE" ]; then
    patch -s -f "$GEN_APPLIED_SCRIPT" "$PATCH_FILE" -o "$GEN_APPLIED_PATCH"
else
    cp "$GEN_APPLIED_SCRIPT" "$GEN_APPLIED_PATCH"
fi


#
# Copy result to the destination
# ==============================
#
cp "$GEN_APPLIED_PATCH" "$DST_DIR/$DST_FILE"
