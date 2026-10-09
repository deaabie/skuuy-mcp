#!/usr/bin/env node

/**
 * Skuuy Tools — Official Model Context Protocol (MCP) Server
 * Connects AI models (Claude, Gemini, Antigravity, Cursor, Cline) to the Skuuy edge toolkit.
 * Zero-log, privacy-preserving, CORS-enabled network & developer primitives.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';

const TOOLS: Tool[] = [
  {
    name: 'skuuy_check_ip',
    description: 'Inspect egress public IP address, geolocation (city, country, coordinates), ASN, ISP, and commercial VPN/proxy status.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: {
          type: 'string',
          description: 'Optional IP address to inspect. If omitted, checks current egress IP.'
        }
      }
    }
  },
  {
    name: 'skuuy_generate_totp',
    description: 'Generate real-time RFC 6238 6-digit Time-Based One-Time Password (TOTP) from a Base32 secret with edge clock drift sync and time window.',
    inputSchema: {
      type: 'object',
      properties: {
        secret: {
          type: 'string',
          description: 'Base32 encoded secret key (e.g. "JBSWY3DPEHPK3PXP")'
        },
        period: {
          type: 'number',
          description: 'Time step in seconds (default: 30)'
        },
        digits: {
          type: 'number',
          description: 'Number of digits (default: 6)'
        }
      },
      required: ['secret']
    }
  },
  {
    name: 'skuuy_temp_mail_generate',
    description: 'Create an active disposable temporary email address with 30-minute validity for signups and verifications without registration.',
    inputSchema: {
      type: 'object',
      properties: {
        prefix: {
          type: 'string',
          description: 'Optional custom username prefix (e.g. "mybot")'
        },
        domain: {
          type: 'string',
          description: 'Optional domain name (e.g. "gmeow.page")'
        }
      }
    }
  },
  {
    name: 'skuuy_temp_mail_get_otp',
    description: 'Directly poll and auto-extract 4-8 digit verification OTP codes and action links from incoming disposable emails.',
    inputSchema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          description: 'The disposable email address to check for OTP codes'
        }
      },
      required: ['email']
    }
  },
  {
    name: 'skuuy_temp_mail_poll_inbox',
    description: 'Poll all incoming email messages (headers, sender, subject, body, extracted links) for a disposable address.',
    inputSchema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          description: 'The disposable email address to poll'
        }
      },
      required: ['email']
    }
  },
  {
    name: 'skuuy_get_proxies',
    description: 'Fetch verified public proxy servers from Skuuy Proxy Hub (50,000+ proxies). Filter by protocol (http, https, socks4, socks5), country code, and limit.',
    inputSchema: {
      type: 'object',
      properties: {
        protocol: {
          type: 'string',
          enum: ['http', 'https', 'socks4', 'socks5'],
          description: 'Filter by proxy protocol'
        },
        country: {
          type: 'string',
          description: 'Filter by ISO 2-letter country code (e.g. "US", "DE", "SG")'
        },
        limit: {
          type: 'number',
          description: 'Maximum number of proxies to return (default: 10, max: 100)'
        }
      }
    }
  },
  {
    name: 'skuuy_resolve_dns',
    description: 'Resolve DNS records (A, AAAA, MX, TXT, CNAME, NS, SOA, CAA) globally using Cloudflare Anycast DoH with DNSSEC validation.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: {
          type: 'string',
          description: 'Domain name to resolve (e.g. "skuuy.com")'
        },
        type: {
          type: 'string',
          description: 'DNS record type (default: "A", supports AAAA, MX, TXT, CNAME, NS, SOA, CAA)'
        }
      },
      required: ['domain']
    }
  },
  {
    name: 'skuuy_scan_ports',
    description: 'Audit remote TCP port exposure on any target host using Cloudflare Edge Sockets.',
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type: 'string',
          description: 'Target hostname or public IP address'
        },
        ports: {
          type: 'string',
          description: 'Comma-separated port numbers (e.g. "22,80,443,3306") or "common"'
        }
      },
      required: ['host']
    }
  },
  {
    name: 'skuuy_search_apis',
    description: 'Search over 1,400+ curated public APIs from Skuuy APIs Hub with authentication, CORS, and category filters.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search keyword (e.g. "weather", "crypto", "animals")'
        },
        category: {
          type: 'string',
          description: 'Category name (e.g. "Finance", "Development", "Weather")'
        },
        cors: {
          type: 'string',
          enum: ['yes', 'no', 'unknown'],
          description: 'Filter by CORS support'
        }
      }
    }
  },
  {
    name: 'skuuy_url_to_markdown',
    description: 'Fetch any public webpage and convert it to clean, token-efficient GitHub Flavored Markdown (GFM), stripping cookie popups, ads, and scripts.',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: 'Target URL to convert into clean markdown'
        }
      },
      required: ['url']
    }
  }
];

async function executeTool(name: string, args: Record<string, any>): Promise<any> {
  const timeoutMs = 15000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    switch (name) {
      case 'skuuy_check_ip': {
        const ip = args.ip?.trim();
        const url = ip ? `https://ip.skuuy.com/api/lookup?ip=${encodeURIComponent(ip)}` : 'https://ip.skuuy.com/api/myip';
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_generate_totp': {
        const secret = encodeURIComponent(args.secret || '');
        const period = args.period || 30;
        const digits = args.digits || 6;
        const url = `https://2fa.skuuy.com/api/totp?secret=${secret}&period=${period}&digits=${digits}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_temp_mail_generate': {
        const params = new URLSearchParams();
        if (args.prefix) params.set('prefix', args.prefix);
        if (args.domain) params.set('domain', args.domain);
        const url = `https://mail.skuuy.com/api/generate?${params.toString()}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_temp_mail_get_otp': {
        const email = encodeURIComponent(args.email || '');
        const url = `https://mail.skuuy.com/api/otp?email=${email}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_temp_mail_poll_inbox': {
        const email = encodeURIComponent(args.email || '');
        const url = `https://mail.skuuy.com/api/inbox?email=${email}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_get_proxies': {
        const params = new URLSearchParams();
        if (args.protocol) params.set('protocol', args.protocol);
        if (args.country) params.set('country', args.country);
        if (args.limit) params.set('limit', String(args.limit));
        const url = `https://proxy.skuuy.com/api/proxies?${params.toString()}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_resolve_dns': {
        const domain = encodeURIComponent(args.domain || 'skuuy.com');
        const type = encodeURIComponent(args.type || 'A');
        const url = `https://dns.skuuy.com/api/resolve?name=${domain}&type=${type}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_scan_ports': {
        const host = encodeURIComponent(args.host || '');
        const ports = encodeURIComponent(args.ports || 'common');
        const url = `https://ports.skuuy.com/api/scan?host=${host}&ports=${ports}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_search_apis': {
        const params = new URLSearchParams();
        if (args.query) params.set('q', args.query);
        if (args.category) params.set('category', args.category);
        if (args.cors) params.set('cors', args.cors);
        const url = `https://apis.skuuy.com/api/v1/apis?${params.toString()}`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      case 'skuuy_url_to_markdown': {
        const targetUrl = encodeURIComponent(args.url || '');
        const url = `https://read.skuuy.com/api/read?url=${targetUrl}&format=json`;
        const res = await fetch(url, { signal: controller.signal });
        return await res.json();
      }

      default:
        throw new Error(`Unknown tool name: "${name}"`);
    }
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  const server = new Server(
    {
      name: 'skuuy-mcp',
      version: '1.0.0',
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
  console.error('Skuuy MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error in Skuuy MCP Server:', error);
  process.exit(1);
});
