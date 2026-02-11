# Sakaki Bridge (NDJSON Protocol)

Sakaki can be controlled from **any AI CLI** by piping JSON lines over stdin/stdout.
Each input line is a JSON request. Each output line is a JSON response.

## Request Format

### HTTP style

```json
{"id":"1","method":"GET","path":"/health"}
```

### Action style (mapped to endpoints)

```json
{"id":"2","action":"navigate","url":"https://example.com"}
```

## Supported Fields

- `id` / `requestId` / `request_id` (optional, echoed back)
- `method` / `httpMethod` (HTTP verb)
- `path` / `endpoint` (HTTP path)
- `body` / `payload` / `args` / `data` (request body)
- `action` / `cmd` (action name → endpoint mapping)
- `headers` (extra headers)
- `query` / `params` / `qs` (query string)
- `adminToken` / `token` / `bearer` (per-request Authorization bearer token)

If `method` + `path` are missing and `action` is provided, the bridge will map it.
Any other fields not in the meta list are folded into the request body.

## Response Format

```json
{"id":"1","ok":true,"status":200,"data":{"ok":true}}
```

On error:

```json
{"id":"1","ok":false,"error":"missing_method_or_path"}
```

## Action Map (Default)

- `navigate` → `POST /navigate`
- `click` → `POST /click`
- `type` → `POST /type`
- `screenshot` → `POST /screenshot`
- `close` → `POST /close`
- `secure.navigate` → `POST /secure/navigate`
- `secure.click` → `POST /secure/click`
- `secure.type` → `POST /secure/type`
- `secure.submit` → `POST /secure/submit-form`
- `remote.start` → `POST /remote/start`
- `remote.stop` → `POST /remote/stop`
- `vault.init` → `POST /vault/init`
- `vault.store` → `POST /vault/store`
- `vault.list` → `GET /vault/list`

## Environment

- `SAKAKI_URL` (default: `http://localhost:18800`)
- `SAKAKI_ADMIN_TOKEN` (default bearer token)

Per-request `adminToken` overrides `SAKAKI_ADMIN_TOKEN`.

## Examples

```bash
echo '{"id":"health","method":"GET","path":"/health"}' | sakaki bridge
echo '{"id":"nav","action":"navigate","url":"https://example.com"}' | sakaki bridge
echo '{"id":"vault","action":"vault.list","adminToken":"change-me"}' | sakaki bridge
```

