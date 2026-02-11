# Ollama CLI Bridge

Run Sakaki via Ollama CLI by piping NDJSON commands into `sakaki bridge`.

## Bash Wrapper

```bash
cd examples/ollama
chmod +x ollama-bridge.sh

./ollama-bridge.sh -- "Open https://example.com"
```

Dry-run (print NDJSON only):

```bash
./ollama-bridge.sh --dry-run -- "Navigate to example.com"
```

## Node Wrapper (more robust)

```bash
node examples/ollama/ollama-bridge.js -- "Open https://example.com"
```

Options:

```bash
node examples/ollama/ollama-bridge.js --model llama3.1 --dry-run -- "Go to example.com"
node examples/ollama/ollama-bridge.js --system-file ./system.txt --prompt-file ./prompt.txt
node examples/ollama/ollama-bridge.js --use-system-flag -- "Open example.com"
```

## Environment

- `OLLAMA_MODEL` (default model)
- `SAKAKI_URL` (Sakaki server URL)
- `SAKAKI_ADMIN_TOKEN` (optional bearer token)
- `SAKAKI_OLLAMA_SYSTEM` (override system prompt)
- `OLLAMA_CMD` (override ollama command)

## Notes

- The model must output **one JSON object per line** (NDJSON).
- If you see no output, use `--dry-run` to inspect what the model is emitting.

