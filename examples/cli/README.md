# CLI Bridges (Codex / Claude / Gemini)

Sakaki can be controlled from any CLI that outputs NDJSON.  
These wrappers reduce user burden by handling system prompts + NDJSON filtering.

## One-liners

```bash
cd examples/cli
chmod +x *.sh

./claude-bridge.sh "Open https://example.com"
./gemini-bridge.sh "Open https://example.com"
./codex-bridge.sh "Open https://example.com"
```

Stable mode (recommended):

```bash
# Claude: de-duplicate repeated NDJSON
SAKAKI_DEDUPLICATE=1 ./claude-bridge.sh "Open https://example.com"

# Codex: uses codex exec + output schema by default
./codex-bridge.sh "Open https://example.com"
```

## Dry run (show NDJSON only)

```bash
node examples/cli/agent-bridge.js --provider claude --dry-run -- "Navigate to example.com"
```

## Custom command

If your CLI needs a custom command, override it:

```bash
CODEX_CMD="codex --auto-edit" node examples/cli/agent-bridge.js --provider codex -- "Open example.com"
CLAUDE_CMD="claude" node examples/cli/agent-bridge.js --provider claude -- "Open example.com"
GEMINI_CMD="gemini" node examples/cli/agent-bridge.js --provider gemini -- "Open example.com"
```

### Codex CLI note

By default, Codex runs via `codex exec --skip-git-repo-check` with an output schema so it can
emit NDJSON. It also writes the last message to a temp file to avoid noisy stdout.
If you want a custom Codex command, set `CODEX_CMD` explicitly.

## Notes

- Outputs are **filtered to valid JSON lines** only.
- If you see no output, use `--dry-run` to inspect the model output.
- Claude sometimes repeats the same line. Set `SAKAKI_DEDUPLICATE=1` or use `--max-lines 1`.

## OS-specific installation

### macOS

```bash
brew install ollama
brew install node
brew install --cask google-chrome
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y nodejs npm curl
curl -fsSL https://ollama.com/install.sh | sh
sudo apt install -y chromium-browser || sudo apt install -y chromium
```

### Windows (PowerShell)

```powershell
winget install Ollama.Ollama
winget install OpenJS.NodeJS
winget install Google.Chrome
```

Notes:
- For Gemini CLI, install the official CLI binary per vendor instructions.
- For Claude/Codex CLI, use the vendor installer or `npm` package if provided.
