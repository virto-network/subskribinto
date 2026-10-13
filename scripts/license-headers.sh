#!/usr/bin/env bash
# Checks that every Rust source file starts with the project's license header.
#
#   scripts/license-headers.sh          # check (CI runs this)
#   scripts/license-headers.sh --fix    # add the header where it's missing

set -euo pipefail

HEADER=$'// Copyright (c) Virto Network\n// SPDX-License-Identifier: MIT'
HEADER_LINES=2

fix=false
case "${1:-}" in
  --fix) fix=true ;;
  "") ;;
  *) echo "usage: $0 [--fix]" >&2; exit 2 ;;
esac

cd "$(git rev-parse --show-toplevel)"

missing=()
while IFS= read -r file; do
  if [[ "$(head -n "$HEADER_LINES" "$file")" != "$HEADER" ]]; then
    missing+=("$file")
  fi
# `sort -u`: files with merge conflicts are listed once per conflict stage.
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' | sort -u)

if [[ ${#missing[@]} -eq 0 ]]; then
  echo "All Rust files have the license header."
  exit 0
fi

if $fix; then
  for file in "${missing[@]}"; do
    { printf '%s\n\n' "$HEADER"; cat "$file"; } > "$file.tmp" && mv "$file.tmp" "$file"
    echo "Added the license header to $file"
  done
  exit 0
fi

echo "These files are missing the license header (run scripts/license-headers.sh --fix):" >&2
printf '  %s\n' "${missing[@]}" >&2
exit 1
