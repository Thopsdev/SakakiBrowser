# Sensitive Data Tags

These tags are used in the safety envelope `data_tags` field.

Tags
- AUTH: API keys, OAuth tokens, session cookies, SSH keys, JWTs, MFA codes
- FIN: card numbers, bank accounts, billing addresses, invoices
- PII: names, addresses, phone numbers, birth dates, ID documents, IP or device IDs
- PHI: medical records, lab results, prescriptions, insurance data
- LEGAL: contracts, NDAs, legal holds, internal investigations
- TRADE_SECRET: customer lists, pricing, roadmaps, sales strategy
- SECURITY_INTERNAL: incident logs, WAF rules, network topology, 0-day details
- MODEL_OPS: system prompts, guardrails, internal evals
- LOCATION: location history, travel logs, calendar attendance
- COMMS: email bodies, DMs, meeting notes, attachments
- PROCUREMENT: purchase orders, approvals, receipts
- AGENT_META: plans, dependencies, queries, execution logs, scopes

Classification Levels
- PUBLIC
- INTERNAL
- CONFIDENTIAL
- VAULT

Rule of Thumb
If disclosure can harm a person or organization, use classification VAULT.
