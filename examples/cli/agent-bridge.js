#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const readline = require('readline');
const { spawn } = require('child_process');

const DEFAULT_SYSTEM =
  'You are a controller for Sakaki Browser. ' +
  'Output ONLY NDJSON (one JSON object per line). No prose. ' +
  'Use action or method/path. If multiple steps are needed, output multiple JSON lines in order. ' +
  'Valid actions: navigate, click, type, screenshot, close, secure.navigate, secure.click, secure.type, secure.submit, remote.start, remote.stop, vault.init, vault.store, vault.list. ' +
  'To open a URL, use action "navigate" with the url field.';

const CODEX_SCHEMA = {
  type: 'object',
  properties: {
    lines: {
      type: 'array',
      items: { type: 'string' }
    }
  },
  required: ['lines'],
  additionalProperties: false
};

function usage() {
  console.log(`
Usage:
  node examples/cli/agent-bridge.js --provider <codex|claude|gemini> -- "<prompt>"

Options:
  --provider <name>        codex | claude | gemini (default: SAKAKI_CLI_PROVIDER)
  --prompt <text>          Provide prompt directly
  --prompt-file <path>     Load prompt from file
  --system <text>          Override system prompt
  --system-file <path>     Load system prompt from file
  --dry-run                Print NDJSON only (no sakaki bridge)
  --raw                    Pass through non-JSON lines to stderr
  --max-lines <n>          Max NDJSON lines forwarded (default: 20)
  --cmd <command>          Override CLI command (e.g., "codex --auto-edit")

Environment:
  SAKAKI_CLI_PROVIDER      Default provider
  SAKAKI_URL               Sakaki server URL
  SAKAKI_ADMIN_TOKEN       Optional bearer token
  CODEX_CMD                Override codex command (optional)
  CLAUDE_CMD               Override claude command (optional)
  GEMINI_CMD               Override gemini command (optional)
  GEMINI_SYSTEM_MD         Used for gemini (auto if not set)
  CODEX_SCHEMA_FILE        Use explicit schema for codex exec (optional)
`);
}

function parseArgs(argv) {
  const args = { promptParts: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--provider') { args.provider = argv[++i]; continue; }
    if (arg === '--prompt') { args.prompt = argv[++i]; continue; }
    if (arg === '--prompt-file') { args.promptFile = argv[++i]; continue; }
    if (arg === '--system') { args.system = argv[++i]; continue; }
    if (arg === '--system-file') { args.systemFile = argv[++i]; continue; }
    if (arg === '--dry-run') { args.dryRun = true; continue; }
    if (arg === '--raw') { args.raw = true; continue; }
    if (arg === '--max-lines') { args.maxLines = parseInt(argv[++i], 10); continue; }
    if (arg === '--cmd') { args.cmd = argv[++i]; continue; }
    if (arg === '--help' || arg === '-h') { args.help = true; continue; }
    if (arg === '--') { args.promptParts.push(...argv.slice(i + 1)); break; }
    args.promptParts.push(arg);
  }
  return args;
}

function readFileIf(pathname) {
  if (!pathname) return null;
  return fs.readFileSync(pathname, 'utf8');
}

function getSakakiBridgePath() {
  return path.resolve(__dirname, '..', '..', 'bin', 'sakaki.js');
}

function buildPrompt(systemPrompt, userPrompt, inlineSystem) {
  if (!inlineSystem) return userPrompt;
  return `SYSTEM:\\n${systemPrompt}\\n\\nUSER:\\n${userPrompt}\\n\\nOutput only NDJSON lines.`;
}

function parseCommand(cmd) {
  if (!cmd) return null;
  const parts = cmd.split(' ').filter(Boolean);
  return { bin: parts[0], args: parts.slice(1) };
}

function sanitizeCodexPayload(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const drop = ['skill', 'why', 'reason', 'analysis', 'thoughts', 'note', 'comment', 'explain'];
  for (const key of drop) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      delete obj[key];
    }
  }
  return obj;
}

function ensureTempSystemFile(systemPrompt) {
  const dir = path.join(os.tmpdir(), 'sakaki');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `system-${Date.now()}-${Math.random().toString(16).slice(2)}.md`);
  fs.writeFileSync(file, systemPrompt, 'utf8');
  return file;
}

function ensureCodexSchemaFile() {
  if (process.env.CODEX_SCHEMA_FILE && fs.existsSync(process.env.CODEX_SCHEMA_FILE)) {
    return process.env.CODEX_SCHEMA_FILE;
  }
  const dir = path.join(os.tmpdir(), 'sakaki');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `codex-schema-${Date.now()}-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(file, JSON.stringify(CODEX_SCHEMA, null, 2), 'utf8');
  return file;
}

function ensureCodexOutputFile() {
  if (process.env.CODEX_OUTPUT_FILE) {
    return process.env.CODEX_OUTPUT_FILE;
  }
  const dir = path.join(os.tmpdir(), 'sakaki');
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, `codex-last-${Date.now()}-${Math.random().toString(16).slice(2)}.txt`);
}

async function readPrompt(args) {
  if (args.prompt) return args.prompt;
  if (args.promptFile) return readFileIf(args.promptFile) || '';
  if (args.promptParts.length) return args.promptParts.join(' ');
  if (!process.stdin.isTTY) {
    return new Promise((resolve) => {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (chunk) => data += chunk);
      process.stdin.on('end', () => resolve(data.trim()));
    });
  }
  return '';
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    process.exit(0);
  }

  const provider = (args.provider || process.env.SAKAKI_CLI_PROVIDER || '').toLowerCase();
  if (!provider) {
    usage();
    process.exit(1);
  }

  const systemPrompt = args.system ||
    readFileIf(args.systemFile) ||
    process.env.SAKAKI_OLLAMA_SYSTEM ||
    DEFAULT_SYSTEM;

  const userPrompt = await readPrompt(args);
  if (!userPrompt) {
    usage();
    process.exit(1);
  }

  let cmdSpec = null;
  let inlineSystem = true;
  let env = { ...process.env };
  let codexOutputFile = null;
  let codexUseOutputFile = false;

  if (provider === 'claude') {
    cmdSpec = parseCommand(args.cmd || process.env.CLAUDE_CMD || 'claude');
    const prompt = buildPrompt(systemPrompt, userPrompt, false);
    cmdSpec.args = [
      ...cmdSpec.args,
      '-p',
      '--output-format', 'text',
      '--system-prompt', systemPrompt,
      prompt
    ];
    inlineSystem = false;
  } else if (provider === 'gemini') {
    cmdSpec = parseCommand(args.cmd || process.env.GEMINI_CMD || 'gemini');
    const prompt = buildPrompt(systemPrompt, userPrompt, false);
    const systemPath = env.GEMINI_SYSTEM_MD || ensureTempSystemFile(systemPrompt);
    env.GEMINI_SYSTEM_MD = systemPath;
    cmdSpec.args = [
      ...cmdSpec.args,
      '-p',
      prompt,
      '--output-format', 'text'
    ];
    inlineSystem = false;
  } else if (provider === 'codex') {
    if (args.cmd || process.env.CODEX_CMD) {
      cmdSpec = parseCommand(args.cmd || process.env.CODEX_CMD);
    } else {
      const schemaPath = ensureCodexSchemaFile();
      const outputFile = ensureCodexOutputFile();
      codexOutputFile = outputFile;
      codexUseOutputFile = true;
      cmdSpec = parseCommand(
        `codex exec --skip-git-repo-check --output-schema ${schemaPath} --output-last-message ${outputFile}`
      );
    }
  } else {
    console.error(`Unknown provider: ${provider}`);
    process.exit(1);
  }

  const promptPayload = buildPrompt(systemPrompt, userPrompt, inlineSystem);

  const cli = spawn(cmdSpec.bin, cmdSpec.args, {
    stdio: ['pipe', 'pipe', 'inherit'],
    env
  });

  if (promptPayload) {
    cli.stdin.write(promptPayload);
  }
  cli.stdin.end();

  let bridge = null;
  if (!args.dryRun) {
    bridge = spawn(process.execPath, [getSakakiBridgePath(), 'bridge'], {
      stdio: ['pipe', 'pipe', 'inherit'],
      env: process.env
    });
    bridge.stdout.pipe(process.stdout);
  }

  const maxLines = Number.isFinite(args.maxLines) ? args.maxLines : 20;
  let forwarded = 0;
  let lastLine = null;
  const dedupe = process.env.SAKAKI_DEDUPLICATE === '1' || provider === 'claude';
  const canSend = () => maxLines <= 0 || forwarded < maxLines;
  const emitLine = (ndjsonLine) => {
    if (!ndjsonLine) return;
    if (!canSend()) return;
    if (dedupe && lastLine === ndjsonLine) return;
    lastLine = ndjsonLine;
    forwarded += 1;
    if (args.dryRun) {
      process.stdout.write(ndjsonLine + '\n');
    } else if (bridge) {
      bridge.stdin.write(ndjsonLine + '\n');
    }
  };
  const rl = readline.createInterface({ input: cli.stdout, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = (line || '').trim();
    if (!trimmed) continue;
    if (provider === 'codex' && codexUseOutputFile) {
      if (args.raw) process.stderr.write(trimmed + '\n');
      continue;
    }

    let obj = null;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      if (args.raw) {
        process.stderr.write(trimmed + '\n');
      }
      continue;
    }

    if (provider === 'codex' && obj && Array.isArray(obj.lines)) {
      for (const rawLine of obj.lines) {
        if (!canSend()) break;
        const ndjsonLine = String(rawLine || '').trim();
        if (!ndjsonLine) continue;
        try {
          const parsed = JSON.parse(ndjsonLine);
          const cleaned = sanitizeCodexPayload(parsed);
          emitLine(JSON.stringify(cleaned));
          continue;
        } catch {
          continue;
        }
      }
      continue;
    }

    if (provider === 'codex') {
      obj = sanitizeCodexPayload(obj);
    }
    emitLine(JSON.stringify(obj));
  }

  if (provider === 'codex' && codexUseOutputFile && codexOutputFile && fs.existsSync(codexOutputFile)) {
    const raw = fs.readFileSync(codexOutputFile, 'utf8').trim();
    let obj = null;
    try {
      obj = JSON.parse(raw);
    } catch {
      obj = null;
    }
    if (obj && Array.isArray(obj.lines)) {
      for (const rawLine of obj.lines) {
        if (!canSend()) break;
        const ndjsonLine = String(rawLine || '').trim();
        if (!ndjsonLine) continue;
        try {
          const parsed = JSON.parse(ndjsonLine);
          const cleaned = sanitizeCodexPayload(parsed);
          emitLine(JSON.stringify(cleaned));
          continue;
        } catch {
          continue;
        }
      }
    }
  }

  if (bridge && bridge.stdin.writable) bridge.stdin.end();
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
