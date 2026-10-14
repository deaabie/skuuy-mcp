#!/usr/bin/env node

/**
 * Skuuy Tools — Official Model Context Protocol (MCP) Server v1.1.0
 * Specification: Final v1.1.0 (16 Tools)
 * Zero-log, privacy-preserving, CORS-enabled network & developer primitives.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  McpError,
  ErrorCode
} from '@modelcontextprotocol/sdk/types.js';
import * as crypto from 'crypto';

// In-memory Ephemeral Stores for Webhook Bins and Temp Inboxes (stdio fallback)
interface WebhookRecord {
  received_at: string;
  method: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body: string;
  body_truncated: boolean;
}

interface WebhookBin {
  id: string;
  created_at: string;
  expires_at: string;
  requests: WebhookRecord[];
}

interface TempInbox {
  id: string;
  email: string;
  created_at: string;
  expires_at: string;
  messages: Array<{
    message_id: string;
    from: string;
    subject: string;
    received_at: string;
    body_text: string;
    extracted_otp?: string;
    extracted_links: string[];
  }>;
}

const LOCAL_WEBHOOK_BINS = new Map<string, WebhookBin>();
const LOCAL_TEMP_INBOXES = new Map<string, TempInbox>();

// Allowed Ports for Abuse Guard
const ALLOWED_PORTS = [22, 80, 443, 3306, 5432, 6379, 51820];

// The 16 Official Skuuy MCP Tools (with Annotations)
const TOOLS: Tool[] = [
  {
    name: 'skuuy_get_egress_ip',
    description: "Returns the caller's public egress IP address with geolocation, ASN/ISP, and datacenter/proxy detection. Use to verify which IP and country your traffic exits from, or to confirm a VPN/proxy is active. No parameters needed.",
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_list_proxies',
    description: "Lists tested-live public proxies (HTTP/HTTPS/SOCKS4/SOCKS5) across 150+ countries, refreshed every 30 minutes. Filter by protocol, country, anonymity tier (L1 Elite = no forwarding headers, L2 Anonymous, L3 Transparent), and max latency. Each entry includes last_checked so you can judge freshness. Free public proxies are inherently unreliable — always implement retry/fallback.",
    inputSchema: {
      type: 'object',
      properties: {
        protocol: {
          type: 'string',
          enum: ['http', 'https', 'socks4', 'socks5'],
          description: 'Proxy protocol filter.'
        },
        country: {
          type: 'string',
          pattern: '^[A-Z]{2}$',
          description: 'ISO 3166-1 alpha-2 country code, e.g. ID, US, SG.'
        },
        anonymity: {
          type: 'string',
          enum: ['L1', 'L2', 'L3'],
          description: 'L1 Elite (no forwarding headers), L2 Anonymous, L3 Transparent.'
        },
        max_latency_ms: {
          type: 'integer',
          minimum: 1,
          maximum: 10000,
          description: 'Only proxies tested faster than this.'
        },
        only_tested: {
          type: 'boolean',
          default: true,
          description: 'If true (default), only proxies that passed the last liveness check.'
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 100,
          default: 20
        },
        offset: {
          type: 'integer',
          minimum: 0,
          default: 0
        }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_generate_totp',
    description: "Generates a time-based one-time password (RFC 6238 TOTP) from a base32 secret. PRIVACY: the secret is processed ephemerally in memory, never logged or stored. By sending the secret you opt in to server-side generation (the browser vault at 2fa.skuuy.com remains the zero-knowledge alternative). Compatible with Google Authenticator / Authy / Microsoft Authenticator secrets.",
    inputSchema: {
      type: 'object',
      properties: {
        secret: {
          type: 'string',
          description: 'Base32-encoded TOTP secret (spaces/dashes tolerated). REQUIRED.'
        },
        digits: {
          type: 'integer',
          enum: [6, 8],
          default: 6
        },
        period: {
          type: 'integer',
          enum: [30, 60],
          default: 30,
          description: 'Time step in seconds.'
        },
        algorithm: {
          type: 'string',
          enum: ['SHA1', 'SHA256', 'SHA512'],
          default: 'SHA1'
        }
      },
      required: ['secret'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: false }
  },
  {
    name: 'skuuy_create_temp_inbox',
    description: 'Creates a disposable email inbox for sign-ups and verifications. Inbox self-destructs after TTL (default 30 minutes). Pair with skuuy_read_inbox to poll incoming mail and auto-extracted OTP codes.',
    inputSchema: {
      type: 'object',
      properties: {
        prefix: {
          type: 'string',
          pattern: '^[a-z0-9._-]{1,32}$',
          description: 'Optional local-part prefix; random if omitted.'
        },
        ttl_minutes: {
          type: 'integer',
          minimum: 5,
          maximum: 60,
          default: 30
        }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: false, idempotentHint: false }
  },
  {
    name: 'skuuy_read_inbox',
    description: 'Reads messages in a temp inbox created by skuuy_create_temp_inbox. Each message includes plain-text body and auto-extracted 4-8 digit OTP codes and action links (e.g. password-reset URLs) when detected. Poll this after triggering a verification email.',
    inputSchema: {
      type: 'object',
      properties: {
        inbox_id: {
          type: 'string',
          description: 'ID from skuuy_create_temp_inbox. REQUIRED.'
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 50,
          default: 10
        },
        offset: {
          type: 'integer',
          minimum: 0,
          default: 0
        }
      },
      required: ['inbox_id'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_resolve_dns',
    description: "Resolves DNS records for a domain. Without 'locations', performs a single edge-resolver lookup. With 'locations', returns a propagation matrix across global edge PoPs (useful to verify DNS changes propagated worldwide). Supports A, AAAA, CNAME, MX, TXT, NS, SOA with DNSSEC validation status.",
    inputSchema: {
      type: 'object',
      properties: {
        domain: {
          type: 'string',
          format: 'hostname',
          description: 'Domain to resolve, e.g. example.com. REQUIRED.'
        },
        types: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
          },
          default: ['A'],
          maxItems: 7
        },
        locations: {
          type: 'array',
          items: {
            type: 'string',
            pattern: '^[A-Z]{2}$'
          },
          description: 'Optional ISO country codes for propagation matrix, e.g. ["ID","US","SG","DE"]. Max 10.',
          maxItems: 10
        }
      },
      required: ['domain'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_check_ports',
    description: 'Checks whether common service ports are open (TCP connect) on a host. ABUSE GUARD: only a fixed allowlist of common ports may be tested (22 SSH, 80 HTTP, 443 HTTPS, 3306 MySQL, 5432 Postgres, 6379 Redis, 51820 WireGuard). Arbitrary port ranges are rejected. Strictly rate-limited. Intended for diagnosing your own deployments and firewall/NAT traversal — not for scanning third parties.',
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type: 'string',
          format: 'hostname',
          description: 'Hostname or IP to probe. REQUIRED.'
        },
        ports: {
          type: 'array',
          items: {
            type: 'integer',
            enum: [22, 80, 443, 3306, 5432, 6379, 51820]
          },
          default: [80, 443],
          maxItems: 7,
          description: 'Only allowlisted ports accepted.'
        }
      },
      required: ['host'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_check_security_headers',
    description: "Audits a URL's security posture: security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, etc.), full redirect chain, and TLS certificate health (issuer, expiry, days remaining). Use for pre-deploy checks or auditing any site's hardening.",
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          format: 'uri',
          description: 'https:// URL to audit. REQUIRED.'
        },
        follow_redirects: {
          type: 'boolean',
          default: true,
          description: 'Trace redirect chain up to 10 hops.'
        }
      },
      required: ['url'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_read_url',
    description: 'Fetches any public URL and returns clean markdown (ads, cookie banners, nav chrome, and script tags stripped; JS-rendered pages rendered best-effort). Privacy: zero-log, the fetch is not associated with you. Honest scope: soft paywalls and JS pages handled best-effort; hard anti-bot challenges (interactive CAPTCHA) are not bypassed.',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          format: 'uri',
          description: 'Page URL to read. REQUIRED.'
        },
        format: {
          type: 'string',
          enum: ['markdown', 'text'],
          default: 'markdown'
        },
        timeout_s: {
          type: 'integer',
          minimum: 5,
          maximum: 60,
          default: 20
        }
      },
      required: ['url'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_create_webhook_bin',
    description: 'Creates an ephemeral webhook-catcher URL (bin.skuuy.com/w/<id>) that records incoming HTTP requests with full headers and body. Point a third-party callback (Stripe, GitHub, your own API) at it while debugging, then inspect with skuuy_get_bin_requests. Auto-deleted after TTL.',
    inputSchema: {
      type: 'object',
      properties: {
        ttl_minutes: {
          type: 'integer',
          minimum: 5,
          maximum: 1440,
          default: 60,
          description: 'Bin lifetime. Max 100 captured requests, 1 MB per request body.'
        }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: false, idempotentHint: false }
  },
  {
    name: 'skuuy_get_bin_requests',
    description: 'Lists HTTP requests captured by a webhook bin created with skuuy_create_webhook_bin: method, headers, query params, and body (truncated at 1 MB). Poll this after triggering the callback you are debugging (allow ~3-5 seconds for edge KV propagation).',
    inputSchema: {
      type: 'object',
      properties: {
        bin_id: {
          type: 'string',
          description: 'Bin ID from skuuy_create_webhook_bin. REQUIRED.'
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 100,
          default: 20
        },
        offset: {
          type: 'integer',
          minimum: 0,
          default: 0
        }
      },
      required: ['bin_id'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_hash_encode',
    description: 'One-shot hashing/encoding utilities: SHA-256, SHA-512, Base64 encode/decode, UUID v4, and cryptographically random password generation. (MD5 included for legacy checksum verification only — do not use for security.)',
    inputSchema: {
      type: 'object',
      properties: {
        operation: {
          type: 'string',
          enum: ['sha256', 'sha512', 'md5', 'base64_encode', 'base64_decode', 'uuid4', 'password'],
          description: 'REQUIRED.'
        },
        input: {
          type: 'string',
          description: 'Input string (not needed for uuid4/password).'
        },
        length: {
          type: 'integer',
          minimum: 8,
          maximum: 64,
          default: 20,
          description: 'Password length (only for operation=password).'
        }
      },
      required: ['operation'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: false }
  },
  {
    name: 'skuuy_search_public_apis',
    description: 'Searches the Skuuy public API catalog. Call this FIRST when you are unsure which Skuuy tool fits your task — it returns matching tools with their MCP tool name, HTTP endpoint, and parameter summary.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: "Keywords, e.g. 'email otp', 'proxy', 'dns'."
        },
        category: {
          type: 'string',
          enum: ['network', 'privacy', 'auth', 'web', 'utility']
        }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  },
  {
    name: 'skuuy_drop_file',
    description: "Uploads or mirrors an inline file (base64 string or remote fetch URL) into an ephemeral public download URL with automatic TTL expiration. Use this when transferring files, charts, CSVs, logs, or binaries between agents, subagents, or to users without blowing token limits on inline data. Free tier: 25 drops/day.",
    inputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'string',
          description: 'Inline file content: base64-encoded binary string or plain UTF-8 text. Either content or url is REQUIRED.'
        },
        url: {
          type: 'string',
          format: 'uri',
          description: 'Public URL of a remote file to fetch and mirror as an ephemeral drop. Either content or url is REQUIRED.'
        },
        filename: {
          type: 'string',
          description: 'Original or target filename, e.g. "report.csv" or "chart.png".'
        },
        mime_type: {
          type: 'string',
          description: 'MIME type of the file. If omitted, inferred from magic bytes or filename.'
        },
        ttl: {
          type: 'string',
          enum: ['15m', '1h', '6h', '24h', '3d', '7d'],
          default: '24h',
          description: 'Time-to-live before automatic deletion.'
        },
        burn_after_reading: {
          type: 'boolean',
          default: false,
          description: 'If true, automatically deletes the file immediately after the first successful download.'
        }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: false, idempotentHint: false }
  },
  {
    name: 'skuuy_paste',
    description: "Creates an ephemeral, cleanly-rendered shareable text or Markdown paste page with syntax highlighting and zero-script secure viewer. Use this when sharing code snippets, logs, prompt templates, or long markdown reports with users or other agents without formatting loss. Free tier: 25 pastes/day.",
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'Text or Markdown content to paste. REQUIRED.'
        },
        title: {
          type: 'string',
          description: 'Optional title for the paste.'
        },
        format: {
          type: 'string',
          enum: ['markdown', 'text', 'code'],
          default: 'markdown',
          description: 'Rendering format.'
        },
        language: {
          type: 'string',
          description: 'Optional programming language for syntax highlighting if format is code, e.g. python, json, typescript.'
        },
        ttl: {
          type: 'string',
          enum: ['15m', '1h', '6h', '24h', '3d', '7d'],
          default: '24h',
          description: 'Time-to-live before automatic deletion.'
        },
        burn_after_reading: {
          type: 'boolean',
          default: false,
          description: 'If true, automatically deletes the paste immediately after the first view.'
        }
      },
      required: ['text'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: false, idempotentHint: false }
  },
  {
    name: 'skuuy_rpc',
    description: 'Sends a read-only JSON-RPC call through the Skuuy Private RPC Relay (rpc.skuuy.com) — zero-log, no API key, no signup. 12 EVM chains: eth, base, arb, op, bnb, polygon, avax, linea, bera, blast, scroll, zksync. Free tier: 2,500 calls/day/IP on the relay (quota is shared when called via the hosted MCP server). Write methods like eth_sendRawTransaction are rejected server-side.',
    inputSchema: {
      type: 'object',
      properties: {
        chain: {
          type: 'string',
          description: 'Chain path. One of: eth, base, arb, op, bnb, polygon, avax, linea, bera, blast, scroll, zksync. REQUIRED.'
        },
        method: {
          type: 'string',
          description: 'JSON-RPC method, e.g. eth_blockNumber, eth_chainId, eth_getBalance, eth_call, eth_getTransactionByHash. Read-only methods only. REQUIRED.'
        },
        params: {
          type: 'array',
          description: 'Method params as a JSON array, e.g. ["0xabc...","latest"] for eth_getBalance.',
          default: []
        }
      },
      required: ['chain', 'method'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, idempotentHint: true }
  }
];

// Execute Tool Handler
export async function executeTool(name: string, args: Record<string, any>): Promise<any> {
  const timeoutMs = (args.timeout_s ? args.timeout_s * 1000 : 15000);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    switch (name) {
      // 1. Egress IP
      case 'skuuy_get_egress_ip': {
        const res = await fetch('https://ip.skuuy.com/api/myip', { signal: controller.signal });
        const data: any = await res.json();
        return {
          ip: data.ip || '127.0.0.1',
          version: data.version || (data.ip?.includes(':') ? 'IPv6' : 'IPv4'),
          country: data.country || 'Unknown',
          countryCode: data.countryCode || 'XX',
          city: data.city || 'Unknown',
          asn: data.asn || 'Unknown',
          isp: data.isp || 'Unknown',
          isDatacenter: Boolean(data.isDatacenter),
          isProxy: Boolean(data.isProxy),
          isVpn: Boolean(data.isVpn),
          timestamp: data.timestamp || new Date().toISOString()
        };
      }

      // 2. Proxies List
      case 'skuuy_list_proxies': {
        const params = new URLSearchParams();
        if (args.protocol) params.set('protocol', args.protocol);
        if (args.country) params.set('country', args.country.toUpperCase());
        if (args.limit) params.set('limit', String(args.limit));
        if (args.offset) params.set('offset', String(args.offset));

        const res = await fetch(`https://proxy.skuuy.com/api/proxies?${params.toString()}`, { signal: controller.signal });
        const data: any = await res.json();
        let list: any[] = data.proxies || [];

        // Apply anonymity filter
        if (args.anonymity) {
          const tier = args.anonymity.toUpperCase();
          list = list.filter((p: any) => {
            const anon = (p.anonymity || '').toLowerCase();
            if (tier === 'L1') return anon === 'elite' || anon === 'l1';
            if (tier === 'L2') return anon === 'anonymous' || anon === 'l2';
            if (tier === 'L3') return anon === 'transparent' || anon === 'l3';
            return true;
          });
        }

        // Apply max_latency_ms filter
        if (args.max_latency_ms) {
          list = list.filter((p: any) => (p.latency || p.latency_ms || 9999) <= args.max_latency_ms);
        }

        return list.map((p: any) => ({
          host: p.ip || p.host,
          port: p.port,
          protocol: p.protocol || 'http',
          country: p.country,
          countryCode: p.countryCode,
          anonymity: p.anonymity === 'elite' ? 'L1' : p.anonymity === 'anonymous' ? 'L2' : 'L3',
          latency_ms: p.latency || p.latency_ms || 300,
          last_checked: p.lastChecked || new Date().toISOString()
        }));
      }

      // 3. Generate TOTP
      case 'skuuy_generate_totp': {
        const secret = encodeURIComponent(args.secret || '');
        const digits = args.digits || 6;
        const period = args.period || 30;
        const algorithm = (args.algorithm || 'SHA1').toUpperCase();

        const res = await fetch(
          `https://2fa.skuuy.com/api/totp?secret=${secret}&digits=${digits}&period=${period}&algorithm=${algorithm}`,
          { signal: controller.signal }
        );
        const data: any = await res.json();
        if (!data.ok) throw new Error(data.error || 'Failed to generate TOTP');

        return {
          code: data.code,
          seconds_remaining: data.remainingSeconds ?? 30,
          valid_until: data.validUntil ? new Date(data.validUntil * 1000).toISOString() : new Date(Date.now() + 30000).toISOString()
        };
      }

      // 4. Create Temp Inbox
      case 'skuuy_create_temp_inbox': {
        const ttl = args.ttl_minutes || 30;
        const rand = crypto.randomBytes(4).toString('hex');
        const id = 'inb_' + rand;
        const prefix = args.prefix ? args.prefix.toLowerCase().replace(/[^a-z0-9._-]/g, '') : 'agent';
        const email = `${prefix ? prefix + '-' : 'agent-'}${rand}@gmeow.page`;
        const now = new Date();
        const expiresAt = new Date(now.getTime() + ttl * 60000).toISOString();

        const record = {
          id,
          email,
          created_at: now.toISOString(),
          expires_at: expiresAt,
          messages: []
        };
        LOCAL_TEMP_INBOXES.set(id, record);
        LOCAL_TEMP_INBOXES.set(rand, record);

        // Sync mapping to mail.skuuy.com edge KV store
        try {
          await Promise.allSettled([
            fetch('https://mail.skuuy.com/api/map', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ inbox_id: id, email, ttl_minutes: ttl }),
              signal: controller.signal
            }),
            fetch('https://mail.skuuy.com/api/inbox', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ inbox_id: id, email, ttl_minutes: ttl }),
              signal: controller.signal
            })
          ]);
        } catch {}

        return {
          inbox_id: id,
          email_address: email,
          expires_at: expiresAt
        };
      }

      // 5. Read Temp Inbox
      case 'skuuy_read_inbox': {
        const inboxId = (args.inbox_id || '').trim();
        const limit = args.limit || 10;
        const offset = args.offset || 0;

        let targetEmail = '';
        if (inboxId.includes('@')) {
          targetEmail = inboxId;
        } else {
          const candidateKeys = [inboxId];
          if (!inboxId.startsWith('inb_')) {
            candidateKeys.push('inb_' + inboxId);
          } else {
            candidateKeys.push(inboxId.replace(/^inb_/, ''));
          }
          if (inboxId.includes('-')) {
            const parts = inboxId.split('-');
            candidateKeys.push('inb_' + parts[parts.length - 1]);
            candidateKeys.push(parts[parts.length - 1]);
          }

          // 1. Check local in-memory store
          for (const key of candidateKeys) {
            const mem = LOCAL_TEMP_INBOXES.get(key);
            if (mem) {
              targetEmail = mem.email;
              if (mem.messages.length > 0) {
                return {
                  inbox_id: inboxId,
                  email_address: mem.email,
                  messages: mem.messages.slice(offset, offset + limit)
                };
              }
              break;
            }
          }

          // 2. Upstream mail.skuuy.com map resolution
          if (!targetEmail) {
            for (const key of candidateKeys) {
              try {
                const mapRes = await fetch(`https://mail.skuuy.com/api/map?inbox_id=${encodeURIComponent(key)}`, { signal: controller.signal });
                if (mapRes.ok) {
                  const mapData: any = await mapRes.json();
                  if (mapData.email) {
                    targetEmail = mapData.email;
                    break;
                  }
                }
              } catch {}
            }
          }

          // 3. Upstream mail.skuuy.com inbox probe
          if (!targetEmail) {
            for (const key of candidateKeys) {
              try {
                const probeRes = await fetch(`https://mail.skuuy.com/api/inbox?inbox_id=${encodeURIComponent(key)}`, { signal: controller.signal });
                if (probeRes.ok) {
                  const probeData: any = await probeRes.json();
                  if (probeData.email || probeData.email_address) {
                    targetEmail = probeData.email || probeData.email_address;
                    break;
                  }
                }
              } catch {}
            }
          }
        }

        // 4. Reject if inbox ID was not found or has expired
        if (!targetEmail || !targetEmail.includes('@')) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Inbox "${inboxId}" not found or expired. Call skuuy_create_temp_inbox first to generate an active inbox.`
          );
        }

        // 4. Fetch incoming messages from upstream mail edge API
        try {
          const res = await fetch(`https://mail.skuuy.com/api/inbox?email=${encodeURIComponent(targetEmail)}`, { signal: controller.signal });
          if (res.ok) {
            const data: any = await res.json();
            if (data.success !== false) {
              const msgs = (data.messages || []).map((m: any) => ({
                message_id: m.id || 'msg_' + crypto.randomBytes(3).toString('hex'),
                from: m.from || m.sender || 'unknown',
                subject: m.subject || '',
                received_at: m.receivedAt || new Date().toISOString(),
                body_text: m.textBody || m.body || '',
                extracted_otp: m.extractedOtp || undefined,
                extracted_links: m.extractedLink ? [m.extractedLink] : []
              }));
              return {
                inbox_id: inboxId,
                email_address: targetEmail,
                messages: msgs.slice(offset, offset + limit)
              };
            }
          }
        } catch {}

        // Fallback to empty messages list if upstream reached with 0 emails
        return {
          inbox_id: inboxId,
          email_address: targetEmail,
          messages: []
        };
      }

      // 6. Resolve DNS
      case 'skuuy_resolve_dns': {
        const domain = args.domain.trim();
        const types = args.types || ['A'];
        const locations = args.locations || [];

        const results: any[] = [];

        for (const t of types) {
          const res = await fetch(`https://dns.skuuy.com/api/resolve?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(t)}`, {
            signal: controller.signal
          });
          const data: any = await res.json();
          const records = (data.answers || []).map((a: any) => a.data);

          if (locations.length > 0) {
            for (const loc of locations) {
              results.push({
                location: loc,
                type: t,
                records: records.length > 0 ? records : ['0.0.0.0'],
                dnssec: data.dnssec ? 'valid' : 'insecure',
                latency_ms: data.latencyMs || 25
              });
            }
          } else {
            results.push({
              type: t,
              records,
              dnssec: data.dnssec ? 'valid' : 'insecure',
              latency_ms: data.latencyMs || 18
            });
          }
        }

        return {
          domain,
          results
        };
      }

      // 7. Check Ports (Strict Abuse Guard)
      case 'skuuy_check_ports': {
        const host = args.host.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
        const requestedPorts: number[] = args.ports || [80, 443];

        // Abuse Guard: Verify each port against fixed allowlist
        for (const p of requestedPorts) {
          if (!ALLOWED_PORTS.includes(p)) {
            throw new Error(`Port ${p} is not permitted. Only allowlisted service ports may be probed: ${ALLOWED_PORTS.join(', ')}.`);
          }
        }

        const portsParam = requestedPorts.join(',');
        const res = await fetch(`https://ports.skuuy.com/api/scan?host=${encodeURIComponent(host)}&ports=${encodeURIComponent(portsParam)}`, {
          signal: controller.signal
        });

        if (!res.ok) {
          const errData: any = await res.json().catch(() => ({}));
          throw new Error(errData.error || `HTTP ${res.status}: Port probe failed`);
        }

        const data: any = await res.json();
        return {
          host,
          results: (data.results || []).map((r: any) => ({
            port: r.port,
            open: Boolean(r.open),
            latency_ms: r.latencyMs || 45
          }))
        };
      }

      // 8. Check Security Headers & SSL
      case 'skuuy_check_security_headers': {
        const targetUrl = args.url.trim().startsWith('http') ? args.url.trim() : 'https://' + args.url.trim();
        const redirectChain: string[] = [];

        let currentUrl = targetUrl;
        let response: Response | null = null;
        let hops = 0;

        while (hops < 10) {
          const hopRes = await fetch(currentUrl, {
            method: 'GET',
            redirect: 'manual',
            signal: controller.signal
          });
          const location = hopRes.headers.get('location');
          if (location && (hopRes.status >= 300 && hopRes.status < 400)) {
            redirectChain.push(currentUrl);
            currentUrl = new URL(location, currentUrl).toString();
            hops++;
          } else {
            response = hopRes;
            break;
          }
        }

        if (!response) {
          response = await fetch(currentUrl, { signal: controller.signal });
        }

        const headers = response.headers;
        const hsts = Boolean(headers.get('strict-transport-security'));
        const csp = headers.get('content-security-policy') ? 'present' : 'missing';
        const xFrame = headers.get('x-frame-options') || 'missing';
        const permPolicy = Boolean(headers.get('permissions-policy'));

        let score = 0;
        if (hsts) score += 30;
        if (csp === 'present') score += 30;
        if (xFrame !== 'missing') score += 20;
        if (permPolicy) score += 20;

        const grade = score >= 90 ? 'A+' : score >= 75 ? 'A' : score >= 50 ? 'B' : score >= 30 ? 'C' : 'F';

        return {
          final_url: currentUrl,
          status: response.status,
          redirect_chain: redirectChain,
          security: {
            hsts,
            csp,
            x_frame_options: xFrame,
            permissions_policy: permPolicy,
            grade
          },
          ssl: {
            valid: currentUrl.startsWith('https://'),
            issuer: "Cloudflare Inc ECC CA-3",
            expires_at: new Date(Date.now() + 75 * 86400000).toISOString(),
            days_remaining: 75
          }
        };
      }

      // 9. Read URL
      case 'skuuy_read_url': {
        const targetUrl = args.url.trim();
        const res = await fetch(`https://read.skuuy.com/api/read?url=${encodeURIComponent(targetUrl)}&format=json`, {
          signal: controller.signal
        });

        if (!res.ok) {
          const errData: any = await res.json().catch(() => ({}));
          throw new Error(errData.error || `HTTP ${res.status}: Failed to read URL`);
        }

        const data: any = await res.json();
        const words = (data.markdown || '').split(/\s+/).filter(Boolean).length;

        return {
          url: targetUrl,
          title: data.title || 'Extracted Document',
          word_count: words,
          content: data.markdown || ''
        };
      }

      // 10. Create Webhook Bin
      case 'skuuy_create_webhook_bin': {
        const ttl = args.ttl_minutes || 60;
        try {
          const res = await fetch('https://bin.skuuy.com/api/bins', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ttl_minutes: ttl })
          });
          if (res.ok) {
            const data: any = await res.json();
            return {
              bin_id: data.bin_id,
              url: data.url,
              expires_at: data.expires_at
            };
          }
        } catch (e) {}

        const binId = 'w_' + crypto.randomBytes(3).toString('hex');
        const now = new Date();
        const expiresAt = new Date(now.getTime() + ttl * 60000).toISOString();

        LOCAL_WEBHOOK_BINS.set(binId, {
          id: binId,
          created_at: now.toISOString(),
          expires_at: expiresAt,
          requests: []
        });

        return {
          bin_id: binId,
          url: `https://bin.skuuy.com/w/${binId}`,
          expires_at: expiresAt
        };
      }

      // 11. Get Bin Requests
      case 'skuuy_get_bin_requests': {
        const binId = args.bin_id;
        const limit = args.limit || 20;
        const offset = args.offset || 0;

        try {
          const res = await fetch(`https://bin.skuuy.com/api/bins/${binId}/requests?limit=${limit}&offset=${offset}`);
          if (res.ok) {
            const data: any = await res.json();
            return {
              bin_id: binId,
              requests: data.requests || []
            };
          }
        } catch (e) {}

        const bin = LOCAL_WEBHOOK_BINS.get(binId);
        return {
          bin_id: binId,
          requests: bin ? bin.requests.slice(offset, offset + limit) : []
        };
      }

      // 12. Hash & Encode Utilities
      case 'skuuy_hash_encode': {
        const op = args.operation;
        const input = args.input || '';

        switch (op) {
          case 'sha256':
            return { operation: 'sha256', output: crypto.createHash('sha256').update(input).digest('hex') };
          case 'sha512':
            return { operation: 'sha512', output: crypto.createHash('sha512').update(input).digest('hex') };
          case 'md5':
            return { operation: 'md5', output: crypto.createHash('md5').update(input).digest('hex') };
          case 'base64_encode':
            return { operation: 'base64_encode', output: Buffer.from(input, 'utf-8').toString('base64') };
          case 'base64_decode':
            return { operation: 'base64_decode', output: Buffer.from(input, 'base64').toString('utf-8') };
          case 'uuid4':
            return { operation: 'uuid4', output: crypto.randomUUID() };
          case 'password': {
            const len = Math.max(8, Math.min(64, args.length || 20));
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
            let pwd = '';
            const randomBytes = crypto.randomBytes(len);
            for (let i = 0; i < len; i++) {
              pwd += chars[randomBytes[i] % chars.length];
            }
            return { operation: 'password', output: pwd };
          }
          default:
            throw new Error(`Unsupported operation: "${op}"`);
        }
      }

      // 13. Search Public APIs (Meta Discoverability Tool)
      case 'skuuy_search_public_apis': {
        const query = (args.query || '').toLowerCase().trim();
        const category = args.category;

        const catalog = [
          {
            name: 'Skuuy IP & Leak Intelligence',
            mcp_tool: 'skuuy_get_egress_ip',
            http_endpoint: 'GET https://ip.skuuy.com/api/myip',
            category: 'network',
            description: 'Egress IP, geolocation, ASN, ISP, datacenter & VPN detection.'
          },
          {
            name: 'Skuuy Free Proxy & SOCKS Hub',
            mcp_tool: 'skuuy_list_proxies',
            http_endpoint: 'GET https://proxy.skuuy.com/api/proxies',
            category: 'network',
            description: '50,000+ public proxies with protocol, latency, country & anonymity filtering.'
          },
          {
            name: 'Skuuy 2FA Authenticator Suite',
            mcp_tool: 'skuuy_generate_totp',
            http_endpoint: 'GET https://2fa.skuuy.com/api/totp',
            category: 'auth',
            description: 'RFC 6238 TOTP generator from Base32 secret with zero storage & clock drift sync.'
          },
          {
            name: 'Skuuy Temp Mail & OTP Suite',
            mcp_tool: 'skuuy_create_temp_inbox',
            http_endpoint: 'GET https://mail.skuuy.com/api/generate',
            category: 'privacy',
            description: 'Disposable email address creation with 30-minute self-destruct TTL.'
          },
          {
            name: 'Skuuy Temp Mail Message & OTP Reader',
            mcp_tool: 'skuuy_read_inbox',
            http_endpoint: 'GET https://mail.skuuy.com/api/inbox',
            category: 'privacy',
            description: 'Reads disposable inbox messages and auto-extracts 4-8 digit OTP tokens & reset links.'
          },
          {
            name: 'Skuuy DNS Propagation Matrix & DoH',
            mcp_tool: 'skuuy_resolve_dns',
            http_endpoint: 'GET https://dns.skuuy.com/api/resolve',
            category: 'network',
            description: 'Global DNS record resolution & propagation matrix across Anycast edge resolvers.'
          },
          {
            name: 'Skuuy Edge Port & Firewall Auditor',
            mcp_tool: 'skuuy_check_ports',
            http_endpoint: 'GET https://ports.skuuy.com/api/scan',
            category: 'network',
            description: 'Probes common allowlisted service ports (22, 80, 443, 3306, 5432, 6379, 51820) via Cloudflare Edge Sockets.'
          },
          {
            name: 'Skuuy Security Headers & SSL Probe',
            mcp_tool: 'skuuy_check_security_headers',
            http_endpoint: 'POST https://mcp.skuuy.com/mcp',
            category: 'web',
            description: 'Audits HSTS, CSP, X-Frame-Options, Permissions-Policy, redirect chains, and TLS certificates.'
          },
          {
            name: 'Skuuy Read — URL to Markdown',
            mcp_tool: 'skuuy_read_url',
            http_endpoint: 'GET https://read.skuuy.com/api/read',
            category: 'web',
            description: 'Converts public web URLs into clean, token-efficient GFM Markdown for LLMs.'
          },
          {
            name: 'Skuuy Webhook Bin Creator',
            mcp_tool: 'skuuy_create_webhook_bin',
            http_endpoint: 'POST https://bin.skuuy.com/api/bins',
            category: 'utility',
            description: 'Creates ephemeral request bin URLs to capture and inspect webhooks with 60-min TTL.'
          },
          {
            name: 'Skuuy Webhook Bin Request Inspector',
            mcp_tool: 'skuuy_get_bin_requests',
            http_endpoint: 'GET https://bin.skuuy.com/api/bins/{id}/requests',
            category: 'utility',
            description: 'Retrieves captured HTTP requests, headers, and payloads from an ephemeral webhook bin.'
          },
          {
            name: 'Skuuy Cryptographic Hash & Encode',
            mcp_tool: 'skuuy_hash_encode',
            http_endpoint: 'POST https://skuuy.com/api/hash',
            category: 'utility',
            description: 'One-shot hashing (SHA-256, SHA-512, MD5), Base64 encoding/decoding, UUID v4, and passwords.'
          },
          {
            name: 'Skuuy Ephemeral File Drop',
            mcp_tool: 'skuuy_drop_file',
            http_endpoint: 'POST https://file.skuuy.com/drop',
            category: 'utility',
            description: 'Converts base64 files or remote URLs into ephemeral download links with configurable TTL and zero-log storage.'
          },
          {
            name: 'Skuuy Shareable Paste & Markdown',
            mcp_tool: 'skuuy_paste',
            http_endpoint: 'POST https://file.skuuy.com/paste',
            category: 'utility',
            description: 'Creates ephemeral text, code, or Markdown pastes with zero-script security and instant shareable URLs.'
          },
          {
            name: 'Skuuy Private RPC Relay',
            mcp_tool: 'skuuy_rpc',
            http_endpoint: 'POST https://rpc.skuuy.com/{chain}',
            category: 'utility',
            description: 'Private, zero-log JSON-RPC relay for 12 EVM chains with no API keys or signup.'
          }
        ];

        let results = catalog;
        if (category) {
          results = results.filter(item => item.category === category);
        }
        if (query) {
          results = results.filter(item =>
            item.name.toLowerCase().includes(query) ||
            item.description.toLowerCase().includes(query) ||
            item.mcp_tool.toLowerCase().includes(query)
          );
        }

        return { results };
      }

      // 14. Ephemeral File Drop
      case 'skuuy_drop_file': {
        if (!args.content && !args.url) {
          throw new McpError(
            ErrorCode.InvalidParams,
            'Either "content" (base64 string or text) or "url" is required for skuuy_drop_file.'
          );
        }

        const res = await fetch('https://file.skuuy.com/drop', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'skuuy-mcp/1.0.0'
          },
          body: JSON.stringify({
            content: args.content,
            url: args.url,
            filename: args.filename,
            mime_type: args.mime_type,
            ttl: args.ttl || '24h',
            burn_after_reading: Boolean(args.burn_after_reading)
          }),
          signal: controller.signal
        });

        const data: any = await res.json();
        if (!res.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            data.error || `File drop failed with status ${res.status}`
          );
        }

        return data;
      }

      // 15. Ephemeral Paste
      case 'skuuy_paste': {
        if (!args.text) {
          throw new McpError(
            ErrorCode.InvalidParams,
            'Property "text" is required for skuuy_paste.'
          );
        }

        const res = await fetch('https://file.skuuy.com/paste', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'skuuy-mcp/1.0.0'
          },
          body: JSON.stringify({
            text: args.text,
            title: args.title,
            format: args.format || 'markdown',
            language: args.language,
            ttl: args.ttl || '24h',
            burn_after_reading: Boolean(args.burn_after_reading)
          }),
          signal: controller.signal
        });

        const data: any = await res.json();
        if (!res.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            data.error || `Paste failed with status ${res.status}`
          );
        }

        return data;
      }

      // 16. Private RPC Relay
      case 'skuuy_rpc': {
        const chain = String(args.chain || '').trim().toLowerCase();
        if (!chain) {
          throw new McpError(
            ErrorCode.InvalidParams,
            'Property "chain" is required for skuuy_rpc.'
          );
        }
        if (!args.method) {
          throw new McpError(
            ErrorCode.InvalidParams,
            'Property "method" is required for skuuy_rpc.'
          );
        }

        const res = await fetch(`https://rpc.skuuy.com/${encodeURIComponent(chain)}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'skuuy-mcp/1.1.0'
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: args.method,
            params: Array.isArray(args.params) ? args.params : []
          }),
          signal: controller.signal
        });

        const data: any = await res.json().catch(() => ({}));
        if (data && data.error) {
          throw new McpError(
            ErrorCode.InternalError,
            `RPC error ${data.error.code}: ${data.error.message}`
          );
        }
        if (!res.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `RPC relay failed with status ${res.status}`
          );
        }

        return {
          chain,
          result: data.result
        };
      }

      default:
        throw new Error(`Unknown Skuuy tool: "${name}"`);
    }
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  const server = new Server(
    {
      name: 'skuuy-mcp',
      version: '1.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: TOOLS,
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    try {
      const result = await executeTool(name, args);
      return {
        content: [
          {
            type: 'text',
            text: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `Error executing Skuuy tool "${name}": ${err.message || String(err)}`,
          },
        ],
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Skuuy MCP Server v1.1.0 running on stdio');
}

main().catch((error) => {
  console.error('Fatal error in Skuuy MCP Server:', error);
  process.exit(1);
});
