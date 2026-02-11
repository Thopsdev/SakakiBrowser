#!/usr/bin/env node
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const DEFAULT_SYSTEM =
  'You are an agent that outputs ONLY NDJSON commands for Sakaki. ' +
  'One JSON object per line. Use action or method/path. No extra text.';

function parseArgs(argv) {
  const args = { promptParts: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--model') {
      args.model = argv[++i];
      continue;
    }
    if (arg === '--system') {
      args.system = argv[++i];
      continue;
    }
    if (arg === '--system-file') {
      args.systemFile = argv[++i];
      continue;
    }
    if (arg === '--prompt-file') {
      args.promptFile = argv[++i];
      continue;
    }
    if (arg === '--use-system-flag') {
      args.useSystemFlag = true;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (arg === '--raw') {
      args.raw = true;
      continue;
    }
    if (arg === '--max-lines') {
      args.maxLines = parseInt(argv[++i], 10);
      continue;
    }
    if (arg === '--ollama-cmd') {
      args.ollamaCmd = argv[++i];
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      args.help = true;
      continue;
    }
    if (arg === '--') {
      args.promptParts.push(...argv.slice(i + 1));
      break;
    }
    args.promptParts.push(arg);
  }
  return args;
}

function usage() {
  console.log(`
Usage:
  node examples/ollama/ollama-bridge.js [options] -- "<prompt>"

Options:
  --model <name>         Ollama model (default: OLLAMA_MODEL or llama3.1)
  --system <text>        System prompt override
  --system-file <path>   Load system prompt from file
  --prompt-file <path>   Load user prompt from file
  --use-system-flag      Use "ollama run --system" (if supported)
  --dry-run              Print NDJSON without executing Sakaki
  --raw                  Pass through non-JSON lines (not recommended)
  --max-lines <n>        Max NDJSON commands to forward (default: 20)
  --ollama-cmd <cmd>     Override ollama command (default: ollama)

Environment:
  OLLAMA_MODEL           Default model name
  SAKAKI_URL             Sakaki server URL
  SAKAKI_ADMIN_TOKEN     Optional bearer token for Sakaki
  SAKAKI_OLLAMA_SYSTEM   System prompt override
`);
}

function readFileIf(pathname) {
  if (!pathname) return null;
  return fs.readFileSync(pathname, 'utf8');
}

function buildPrompt(systemPrompt, userPrompt, useSystemFlag) {
  if (useSystemFlag) return userPrompt;
  return `SYSTEM:\\n${systemPrompt}\\n\\nUSER:\\n${userPrompt}\\n\\nOutput only NDJSON lines.`;
}

function getSakakiPath() {
  return path.resolve(__dirname, '..', '..', 'bin', 'sakaki.js');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    process.exit(0);
  }

  const model = args.model || process.env.OLLAMA_MODEL || 'llama3.1';
  const systemPrompt = args.system ||
    readFileIf(args.systemFile) ||
    process.env.SAKAKI_OLLAMA_SYSTEM ||
    DEFAULT_SYSTEM;
  const maxLines = Number.isFinite(args.maxLines) ? args.maxLines : 20;
  const ollamaCmd = args.ollamaCmd || process.env.OLLAMA_CMD || 'ollama';

  let userPrompt = '';
  if (args.promptFile) {
    userPrompt = readFileIf(args.promptFile) || '';
  } else if (args.promptParts.length > 0) {
    userPrompt = args.promptParts.join(' ');
  } else if (!process.stdin.isTTY) {
    userPrompt = await new Promise((resolve) => {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => data += chunk);
      process.stdin.on('end', () => resolve(data.trim()));
    });
  }

  if (!userPrompt) {
    usage();
    process.exit(1);
  }

  const ollamaArgs = ['run', model];
  if (args.useSystemFlag) {
    ollamaArgs.push('--system', systemPrompt);
  }

  const ollama = spawn(ollamaCmd, ollamaArgs, {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: process.env
  });

  const promptPayload = buildPrompt(systemPrompt, userPrompt, args.useSystemFlag);
  ollama.stdin.write(promptPayload);
  ollama.stdin.end();

  let bridge = null;
  if (!args.dryRun) {
    bridge = spawn(process.execPath, [getSakakiPath(), 'bridge'], {
      stdio: ['pipe', 'pipe', 'inherit'],
      env: process.env
    });
    bridge.stdout.pipe(process.stdout);
  }

  let forwarded = 0;
  const rl = readline.createInterface({ input: ollama.stdout, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = (line || '').trim();
    if (!trimmed) continue;

    let obj = null;
    try {
      obj = JSON.parse(trimmed);
    } catch (e) {
      if (args.raw) {
        process.stdout.write(trimmed + '\n');
      }
      continue;
    }

    forwarded += 1;
    if (args.dryRun) {
      process.stdout.write(JSON.stringify(obj) + '\n');
    } else if (bridge) {
      bridge.stdin.write(JSON.stringify(obj) + '\n');
    }

    if (maxLines > 0 && forwarded >= maxLines) {
      break;
    }
  }

  if (bridge && bridge.stdin.writable) bridge.stdin.end();
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});

