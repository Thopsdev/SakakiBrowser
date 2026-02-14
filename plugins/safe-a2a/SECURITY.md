# Security Policy

This plugin is designed to reduce agent-to-agent data leakage and confused-deputy risks.

Reporting
- Email: security@example.com
- Response time: best effort

Supported Versions
- This repository is a spec-first MVP. Treat all changes as potentially breaking.

Security Principles
- Do not carry raw secrets in message payloads
- Require signed envelopes with short TTL
- Enforce allowlists and tool constraints at runtime
- Log only metadata and hashes
