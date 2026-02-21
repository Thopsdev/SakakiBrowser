#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

IGNORE_FILE=".secret-scan-ignore"
PATTERN='ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----'

declare -a IGNORES=()
if [[ -f "$IGNORE_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    IGNORES+=("$line")
  done < "$IGNORE_FILE"
fi

should_ignore() {
  local file="$1"
  local rule
  for rule in "${IGNORES[@]}"; do
    if [[ "$file" =~ $rule ]]; then
      return 0
    fi
  done
  return 1
}

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
found=0

while IFS= read -r file; do
  should_ignore "$file" && continue
  if rg -n -I --no-heading -e "$PATTERN" "$file" >> "$tmp"; then
    found=1
  fi
done < <(git ls-files)

if [[ "$found" -eq 1 ]]; then
  echo "Secret scan failed. Potential sensitive strings found:"
  cat "$tmp"
  exit 1
fi

echo "Secret scan passed."
