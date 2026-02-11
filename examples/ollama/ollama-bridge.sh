#!/usr/bin/env bash
set -euo pipefail

MODEL="${OLLAMA_MODEL:-llama3.1}"
SAKAKI_URL="${SAKAKI_URL:-http://localhost:18800}"
SYSTEM_PROMPT="${SAKAKI_OLLAMA_SYSTEM:-You are an agent that outputs ONLY NDJSON commands for Sakaki. One JSON object per line. Use action or method/path. No extra text.}"

usage() {
  cat <<'EOF'
Usage:
  ./ollama-bridge.sh [--model <name>] [--dry-run] -- "<prompt>"

Examples:
  ./ollama-bridge.sh -- "Open example.com"
  OLLAMA_MODEL=llama3.1 ./ollama-bridge.sh --dry-run -- "Navigate to example.com"

Environment:
  OLLAMA_MODEL              Default model (llama3.1)
  SAKAKI_URL                Sakaki server URL
  SAKAKI_ADMIN_TOKEN        Optional bearer token (forwarded to sakaki bridge)
  SAKAKI_OLLAMA_SYSTEM      System prompt override
EOF
}

DRY_RUN=0
PROMPT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model)
      MODEL="$2"; shift 2;;
    --dry-run)
      DRY_RUN=1; shift;;
    --help|-h)
      usage; exit 0;;
    --)
      shift; PROMPT="$*"; break;;
    *)
      if [[ -z "$PROMPT" ]]; then
        PROMPT="$1"; shift
      else
        PROMPT="$PROMPT $1"; shift
      fi
      ;;
  esac
done

if [[ -z "${PROMPT// }" ]]; then
  echo "Prompt required." >&2
  usage
  exit 1
fi

echo "[ollama-bridge] model=$MODEL url=$SAKAKI_URL" >&2

FULL_PROMPT="SYSTEM:\n${SYSTEM_PROMPT}\n\nUSER:\n${PROMPT}\n\nOutput only NDJSON lines."

if [[ "$DRY_RUN" -eq 1 ]]; then
  ollama run "$MODEL" "$FULL_PROMPT" | grep -E '^[[:space:]]*\\{.*\\}[[:space:]]*$'
else
  ollama run "$MODEL" "$FULL_PROMPT" \
    | grep -E '^[[:space:]]*\\{.*\\}[[:space:]]*$' \
    | SAKAKI_URL="$SAKAKI_URL" sakaki bridge
fi

