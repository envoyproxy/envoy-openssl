#!/bin/bash

set -e # Quit on error
#set -x # Echo commands

function status {
    cmake -E cmake_echo_color --blue "$1"
}

function error {
    cmake -E cmake_echo_color --red "$1"
    exit 1
}


#
# Get command line args
#
CMAKE_CURRENT_SOURCE_DIR="${1?"CMAKE_CURRENT_SOURCE_DIR not specified"}"
CMAKE_CURRENT_BINARY_DIR="${2?"CMAKE_CURRENT_BINARY_DIR not specified"}"
SRC_FILE="${3?"SRC_FILE not specified"}" # e.g. crypto/err/internal.h
DST_FILE="${4?"DST_FILE not specified"}" # e.g. source/crypto/err/internal.h

SRC_DIR="$CMAKE_CURRENT_SOURCE_DIR/external/boringssl"
PATCH_DIR="$CMAKE_CURRENT_SOURCE_DIR/patch"
GEN_DIR="$CMAKE_CURRENT_BINARY_DIR/generate"

#
# Check/Ensure the inputs and outputs exist
#
[[ -d "$SRC_DIR" ]] || error "SRC_DIR $SRC_DIR does not exist"
[[ -f "$SRC_DIR/$SRC_FILE" ]] || error "SRC_FILE $SRC_FILE does not exist in $SRC_DIR"
[[ -d "$PATCH_DIR" ]] || error "PATCH_DIR $PATCH_DIR does not exist"
mkdir -p "$(dirname "$GEN_DIR/$DST_FILE")"


#
# Phase 1 - Comment everything out by default
# ===========================================
#
# Attempts to comment out everything in the specified file, without unecessarily
# commenting out blank lines, existing line comments, or existing block comments
#
GEN_APPLIED_COMMENTS="$GEN_DIR/$DST_FILE.0.applied.comments"
sed -e 's|^|// |' -e 's|^// $||' -e 's|^// //|//|' -e 's|^// /\*|/*|' \
    -e 's|^//  \*$| *|' -e 's|^//  \* | * |' -e 's|^//  \*/$| */|' \
    "$SRC_DIR/$SRC_FILE" > "$GEN_APPLIED_COMMENTS"


#
# Phase 2 - Apply script file from $PATCH_DIR
# ===========================================
#
PATCH_SCRIPT="$PATCH_DIR/$DST_FILE.sh"
GEN_APPLIED_SCRIPT="$GEN_DIR/$DST_FILE.1.applied.script"
cp "$GEN_APPLIED_COMMENTS" "$GEN_APPLIED_SCRIPT"
if [ -f "$PATCH_SCRIPT" ]; then
    "$PATCH_SCRIPT" "$GEN_APPLIED_SCRIPT"
fi


#
# Phase 3 - Apply patch file from $PATCH_DIR
# ==========================================
#
PATCH_FILE="$PATCH_DIR/$DST_FILE.patch"
GEN_APPLIED_PATCH="$GEN_DIR/$DST_FILE.2.applied.patch"
if [ -f "$PATCH_FILE" ]; then
    patch -s -f "$GEN_APPLIED_SCRIPT" "$PATCH_FILE" -o "$GEN_APPLIED_PATCH"
else
    cp "$GEN_APPLIED_SCRIPT" "$GEN_APPLIED_PATCH"
fi


#
# Phase 4 - Copy result to the destination or create/update the patch file
# ========================================================================
#
# If the destination file doesn't exist, just copy the last scratch file to it.
#
# Otherwise, check if the previous content matches the new content that we just
# generated. If it doesn't match, then we assume that that the destination file
# has been hand edited. Therefore, create or update the corresponding patch file
# so that the generated content does match the destination content (or at least
# it will next time we run).
#
# The most important thing is never to modify the destination content because
# doing so may cause hand edits to be discarded.
#
if [ ! -f "$CMAKE_CURRENT_SOURCE_DIR/$DST_FILE" ]; then
    mkdir -p "$(dirname "$CMAKE_CURRENT_SOURCE_DIR/$DST_FILE")"
    cp "$GEN_APPLIED_PATCH" "$CMAKE_CURRENT_SOURCE_DIR/$DST_FILE"
    status "Created $DST_FILE"
else # "$CMAKE_CURRENT_SOURCE_DIR/$DST_FILE" exists
    if ! cmp -s "$GEN_APPLIED_PATCH" "$CMAKE_CURRENT_SOURCE_DIR/$DST_FILE"; then
        [[ -f "$PATCH_FILE" ]] || mkdir -p "$(dirname "$PATCH_FILE")"
        if diff -au --label "a/$DST_FILE" "$GEN_APPLIED_SCRIPT" --label "b/$DST_FILE" "$CMAKE_CURRENT_SOURCE_DIR/$DST_FILE" > "$PATCH_FILE"; then
            rm -f "$PATCH_FILE"
            status "Deleted patch/$(realpath -m --relative-to="$PATCH_DIR" "$PATCH_FILE")"
        else
            status "Updated patch/$(realpath -m --relative-to="$PATCH_DIR" "$PATCH_FILE")"
        fi
    fi
fi


#
# Add the  generated file to .gitignore file so it doesn't get checked into git
#
GITIGNORE="$CMAKE_CURRENT_SOURCE_DIR/.gitignore"
if ! grep "^$DST_FILE$" "$GITIGNORE" > /dev/null; then
    if true; then
        status "Added $DST_FILE to .gitignore"
        echo "$DST_FILE" | sort -u -o "$GITIGNORE" - "$GITIGNORE"
    else
        echo "Please add $DST_FILE to $GITIGNORE"
    fi
fi


