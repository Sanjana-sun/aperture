#!/bin/sh
# GitHub Pages serves docs/ only, so the modules are copied there rather than
# imported from ../src. That copy is the one thing in this repo that can drift
# without anything failing, so copying is a command and drift is a test.
set -e
cd "$(dirname "$0")"
for f in src/*.js; do cp "$f" "docs/$(basename "$f")"; done
cp test/export.zip test/meta.png test/meta.webp docs/ 2>/dev/null || true
echo "synced src/ and fixtures into docs/"
