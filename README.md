# Skuuy Tools MCP Server (`skuuy-mcp`)

> Official Model Context Protocol (MCP) Server for the [Skuuy Tools Ecosystem](https://skuuy.com).
> Gives autonomous AI agents (Claude, Gemini, Antigravity, Cursor, Cline) zero-friction access to privacy-preserving network diagnostics, authentication primitives, and developer utilities.

## Features & Exposed Tools

All tools are **100% free**, require **no API keys**, and operate under a strict **zero-log policy**:

1. **`skuuy_get_egress_ip`**: Returns the caller's public egress IP address with geolocation, ASN/ISP, and datacenter/proxy detection. Use to verify which IP and country your traffic exits from, or to confirm a VPN/proxy is active.
2. **`skuuy_list_proxies`**: Lists tested-live public proxies (HTTP/HTTPS/SOCKS4/SOCKS5) across 150+ countries, refreshed every 30 minutes. Filter by protocol, country, anonymity tier (L1 Elite, L2 Anonymous, L3 Transparent), and max latency. Free public proxies are inherently unreliable — always implement retry/fallback.
3. **`skuuy_generate_totp`**: Generates a time-based one-time password (RFC 6238 TOTP) from a base32 secret. Privacy: the secret is processed ephemerally in memory, never logged or stored. Compatible with Google Authenticator / Authy / Microsoft Authenticator secrets.
4. **`skuuy_create_temp_inbox`**: Creates a disposable email inbox for sign-ups and verifications. Inbox self-destructs after TTL (default 30 minutes).
5. **`skuuy_read_inbox`**: Reads messages in a temp inbox created by `skuuy_create_temp_inbox`. Each message includes plain-text body and auto-extracted 4–8 digit OTP codes and action links (e.g. password-reset URLs) when detected.
6. **`skuuy_resolve_dns`**: Resolves DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA) for a domain via Cloudflare Anycast DoH with DNSSEC validation. Optional global propagation matrix across edge PoPs.
7. **`skuuy_check_ports`**: Checks whether common service ports are open (TCP connect) on a host. Abuse guard: only a fixed allowlist may be tested (22 SSH, 80 HTTP, 443 HTTPS, 3306 MySQL, 5432 Postgres, 6379 Redis, 51820 WireGuard). Intended for diagnosing your own deployments — not for scanning third parties.
8. **`skuuy_check_security_headers`**: Audits a URL's security posture: security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, etc.), full redirect chain, and TLS certificate health (issuer, expiry, days remaining).
9. **`skuuy_read_url`**: Fetches any public URL and returns clean markdown (ads, cookie banners, nav chrome, and script tags stripped; JS-rendered pages rendered best-effort). Honest scope: hard anti-bot challenges (interactive CAPTCHA) are not bypassed.
10. **`skuuy_create_webhook_bin`**: Creates an ephemeral webhook-catcher URL (`bin.skuuy.com/w/<id>`) that records incoming HTTP requests with full headers and body. Point a third-party callback (Stripe, GitHub, your own API) at it while debugging, then inspect with `skuuy_get_bin_requests`. Auto-deleted after TTL.
11. **`skuuy_get_bin_requests`**: Lists HTTP requests captured by a webhook bin created with `skuuy_create_webhook_bin`: method, headers, query params, and body (truncated at 1 MB).
12. **`skuuy_hash_encode`**: One-shot hashing/encoding utilities: SHA-256, SHA-512, Base64 encode/decode, UUID v4, and cryptographically random password generation. (MD5 included for legacy checksum verification only — do not use for security.)
13. **`skuuy_search_public_apis`**: Searches 1,400+ public developer APIs with authentication, CORS, and health status filters.
14. **`skuuy_drop_file`**: Share a file with the user or anyone else: pass file content as base64 (or a public URL for the server to fetch) and get back a short-lived public download link. Zero-log, auto-deletes after TTL (max 7 days), optional burn-after-reading. Free tier: 25 drops/day, 10 MB max per file.
15. **`skuuy_paste`**: Share a text/markdown snippet as a short-lived public page. Same zero-log TTL model as file drops. Free tier: 25 pastes/day.

> **Note on paid REST endpoints:** `skuuy_drop_file`, `skuuy_paste`, and the REST `read_url` are free up to a daily quota on their REST endpoints (`file.skuuy.com`, `read.skuuy.com`), then $0.005 USDC per request via x402 on Base. The MCP tools themselves are always free and rate-limited — MCP clients aren't x402-aware, so the tools never paywall.

---

## Installation & Setup

### 1. Claude Desktop
Add to your `claude_desktop_config.json` (`%APPDATA%\Claude\claude_desktop_config.json` on Windows, or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "skuuy": {
      "command": "npx",
      "args": ["-y", "skuuy-mcp"]
    }
  }
}
```

### 2. Cursor IDE
Add to `.cursor/mcp.json` or Cursor Settings -> Features -> MCP:

```json
{
  "mcpServers": {
    "skuuy": {
      "command": "npx",
      "args": ["-y", "skuuy-mcp"]
    }
  }
}
```

### 3. Antigravity / Google Agents
Add to your agent MCP configuration:

```json
{
  "mcpServers": {
    "skuuy": {
      "command": "node",
      "args": ["D:/Skuuy/skuuy-mcp/dist/index.js"]
    }
  }
}
```

---

## Local Development

```bash
git clone https://github.com/deaabie/skuuy-mcp.git
cd skuuy-mcp
npm install
npm run build
npm start
```

## Privacy & Security

- Zero-Knowledge: 2FA secrets and hashes are processed in-memory and never logged to disks or telemetry databases.
- Strict TTL: Temporary emails, webhook bins, and shared files expire automatically.
- SSRF Safe: Port scanning and web reading restrict RFC 1918 private subnets and loopback addresses.
- Abuse Guards: Port checks are allowlist-only; file drops are quota-bucketed by IPv6 /64.

## License

MIT © [Skuuy Tools](https://skuuy.com)
