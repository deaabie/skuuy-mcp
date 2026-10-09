# Skuuy Tools MCP Server (`skuuy-mcp`)

> Official Model Context Protocol (MCP) Server for the [Skuuy Tools Ecosystem](https://skuuy.com).
> Gives autonomous AI agents (Claude, Gemini, Antigravity, Cursor, Cline) zero-friction access to privacy-preserving network diagnostics, authentication primitives, and developer utilities.

## Features & Exposed Tools

All tools are **100% free**, require **no API keys**, and operate under a strict **zero-log policy**:

1. **`skuuy_check_ip`**: Inspect public egress IP address, geolocation (city, country), ASN, ISP, and commercial VPN/proxy status.
2. **`skuuy_generate_totp`**: Generate real-time RFC 6238 6-digit TOTP verification codes from Base32 secrets with edge clock drift sync.
3. **`skuuy_temp_mail_generate`**: Create an active disposable email inbox with 30-minute validity.
4. **`skuuy_temp_mail_get_otp`**: Poll and auto-extract 4-8 digit OTP tokens or password reset links from disposable inboxes.
5. **`skuuy_temp_mail_poll_inbox`**: Retrieve all incoming MIME-parsed emails and headers.
6. **`skuuy_get_proxies`**: Fetch verified public HTTP, HTTPS, SOCKS4, and SOCKS5 proxies filtered by country, protocol, and latency.
7. **`skuuy_resolve_dns`**: Resolve DNS records (A, AAAA, MX, TXT, CNAME, NS, SOA, CAA) globally via Cloudflare Anycast DoH with DNSSEC validation.
8. **`skuuy_scan_ports`**: Audit remote TCP port exposure on any host using Cloudflare Edge Sockets (`cloudflare:sockets`).
9. **`skuuy_search_apis`**: Search 1,400+ public developer APIs with authentication, CORS, and health status filters.
10. **`skuuy_url_to_markdown`**: Convert any public web URL to clean, token-efficient GitHub Flavored Markdown (stripping ads, scripts, and popups).

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
- Strict TTL: Temporary emails and messages expire automatically after 30 minutes.
- SSRF Safe: Port scanning and web reading restrict RFC 1918 private subnets and loopback addresses.

## License

MIT © [Skuuy Tools](https://skuuy.com)
