# Production A2A Template

This is a minimal production template for running Sakaki Browser with Safe A2A enforcement.

## 1) Environment

Create a runtime env file (example only):

```bash
PORT=18800
SAKAKI_BIND=127.0.0.1
SAKAKI_ADMIN_TOKEN=change-me

# Strict safety posture
SAKAKI_MODE=strict
SAKAKI_PROXY_REQUIRE_ALLOWLIST=1

# Safe A2A
SAKAKI_A2A_ENABLE=1
SAKAKI_A2A_MODE=strict
SAKAKI_A2A_SHARED_SECRET=change-me
SAKAKI_A2A_ALLOWED_PURPOSES=research.compile_brief
SAKAKI_A2A_RECEIVER_AUD=agent:sakai://worker/search

# Allowlist for Secure/Vault lanes (use *.example.com to allow subdomains)
SAKAKI_SECURE_ALLOWED_DOMAINS=example.com,login.example.com
```

## 2) Reverse proxy

Terminate TLS at a reverse proxy and keep Sakaki bound to localhost.

```nginx
server {
  listen 443 ssl;
  server_name sakaki.example.com;

  ssl_certificate     /etc/letsencrypt/live/sakaki.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/sakaki.example.com/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:18800;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```

## 3) Run

```bash
npm install
npm start
```

## 4) Client envelope requirements

- Every request must include a safety envelope (`sakai:safety-envelope/1`)
- `constraints.allowed_domains` must be set
- `purpose` must be in `SAKAKI_A2A_ALLOWED_PURPOSES`

See `plugins/safe-a2a/README.md` for signing and examples.
