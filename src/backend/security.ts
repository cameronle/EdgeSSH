const encoder = new TextEncoder();
const decoder = new TextDecoder();
const TICKET_TTL_MS = 60_000;

interface TicketPayload {
  exp: number;
  nonce: string;
  ip: string;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Invalid Base64URL value');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  if (toBase64Url(Uint8Array.from(binary, (char) => char.charCodeAt(0))) !== value) throw new Error('Non-canonical Base64URL value');
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function createTicket(secret: Uint8Array, ip: string): Promise<{ ticket: string; expiresAt: number }> {
  const expiresAt = Date.now() + TICKET_TTL_MS;
  const payload: TicketPayload = { exp: expiresAt, nonce: crypto.randomUUID(), ip };
  const encodedPayload = toBase64Url(encoder.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', new Uint8Array(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(encodedPayload)));
  return { ticket: `${encodedPayload}.${toBase64Url(signature)}`, expiresAt };
}

export async function verifyTicket(secret: Uint8Array, ticket: string, ip: string): Promise<boolean> {
  const parts = ticket.split('.');
  if (parts.length !== 2 || parts[0].length > 1024 || parts[1].length > 128) return false;
  try {
    const key = await crypto.subtle.importKey('raw', new Uint8Array(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, new Uint8Array(fromBase64Url(parts[1])), encoder.encode(parts[0]));
    if (!valid) return false;
    const payload = JSON.parse(decoder.decode(fromBase64Url(parts[0]))) as Partial<TicketPayload>;
    // 不做强一致的 IP 绑定校验（payload.ip === ip）：当站点被反代/CDN（如腾讯云
    // EdgeOne）套用时，Cloudflare 注入的 CF-Connecting-IP 是反代回源节点 IP，而
    // 非浏览器真实 IP；多节点回源会让 POST /api/session 与 GET /api/ssh 两次请求
    // 的 CF-Connecting-IP 不一致，导致 ticket 被误判失效，前端表现为概率性
    // "WebSocket 传输错误"。ticket 已有 HMAC-SHA256 签名 + 60s 短过期 + 一次性
    // 消费（nonce）三重保护，足以抵御重放，IP 绑定在此场景下冗余且误伤。
    // ip 参数与 payload.ip 保留以备审计。
    return typeof payload.exp === 'number' && Number.isFinite(payload.exp)
      && payload.exp >= Date.now() && payload.exp <= Date.now() + TICKET_TTL_MS + 5000
      && typeof payload.nonce === 'string'
      && /^[0-9a-f-]{36}$/i.test(payload.nonce);
  } catch {
    return false;
  }
}

function isIPv4(host: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)
    && host.split('.').every((part) => Number(part) <= 255 && (part === '0' || !part.startsWith('0')));
}

function normalizeIPv6(host: string): string {
  try {
    return new URL(`http://[${host}]`).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return host.toLowerCase();
  }
}

function parseIPv6Groups(value: string): number[] | null {
  const normalized = value.toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(normalized) || normalized.includes(':::')) return null;
  const expand = (part: string): number[] | null => {
    if (!part) return [];
    const result: number[] = [];
    for (const token of part.split(':')) {
      if (!token) return null;
      if (token.includes('.')) {
        if (!isIPv4(token)) return null;
        const [a, b, c, d] = token.split('.').map(Number);
        result.push((a << 8) | b, (c << 8) | d);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
        result.push(Number.parseInt(token, 16));
      }
    }
    return result;
  };
  const marker = normalized.indexOf('::');
  if (marker >= 0 && normalized.indexOf('::', marker + 1) >= 0) return null;
  if (marker < 0) {
    const groups = expand(normalized);
    return groups?.length === 8 ? groups : null;
  }
  const left = expand(normalized.slice(0, marker));
  const right = expand(normalized.slice(marker + 2));
  if (!left || !right || left.length + right.length >= 8) return null;
  return [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
}

function embeddedIPv4(groups: number[], offset: number): string | null {
  if (groups.length !== 8 || offset < 0 || offset + 1 >= groups.length) return null;
  const numeric = (groups[offset] * 0x10000 + groups[offset + 1]) >>> 0;
  return `${numeric >>> 24}.${numeric >>> 16 & 0xff}.${numeric >>> 8 & 0xff}.${numeric & 0xff}`;
}

export function isPrivateAddress(host: string): boolean {
  const value = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (value === 'localhost' || value.endsWith('.localhost') || value === '0.0.0.0'
    || value === 'metadata.google.internal' || value.endsWith('.internal')) return true;
  if (isIPv4(value)) {
    const [a, b, c] = value.split('.').map(Number);
    return a === 0 || a === 10 || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 0 && c === 0)
      || (a === 192 && b === 0 && c === 2)
      || (a === 192 && b === 88 && c === 99)
      || (a === 192 && b === 168)
      || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113)
      || a >= 224;
  }
  if (!value.includes(':')) return false;
  const ipv6 = normalizeIPv6(value);
  const groups = parseIPv6Groups(ipv6);
  if (!groups) return true;
  if (groups[0] === 0 && groups.slice(1).every((group) => group === 0)) return true;
  if (groups[0] === 0 && groups.slice(1, 7).every((group) => group === 0) && groups[7] === 1) return true;

  // IPv4-compatible (::/96) and IPv4-mapped (::ffff:0:0/96) forms must
  // receive the same private/reserved-address treatment as their IPv4 value.
  const compatible = groups.slice(0, 6).every((group) => group === 0);
  const mapped = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff;
  if (compatible || mapped) {
    const address = embeddedIPv4(groups, 6);
    if (address) return isPrivateAddress(address);
  }

  const first = groups[0], second = groups[1];
  if ((first & 0xfe00) === 0xfc00 // Unique local (fc00::/7)
    || (first & 0xffc0) === 0xfe80 // Link-local (fe80::/10)
    || (first & 0xffc0) === 0xfec0 // Deprecated site-local (fec0::/10)
    || first === 0x0100 // Discard-only (100::/64)
    || (first === 0x2001 && second === 0) // Teredo (2001::/32)
    || (first === 0x2001 && (second & 0xfff0) === 0x0010) // ORCHID
    || (first === 0x2001 && second === 0x0002) // Benchmarking (2001:2::/48)
    || (first === 0x2001 && second === 0x0db8) // Documentation
    || (first & 0xff00) === 0xff00 // Multicast
  ) return true;

  // A 6to4 address can embed a private IPv4 target in groups 2 and 3.
  if (first === 0x2002) {
    const address = embeddedIPv4(groups, 2);
    if (address && isPrivateAddress(address)) return true;
  }
  return false;
}

// cloudflare:sockets connect() joins hostname and port into a single
// "host:port" authority string, so an IPv6 literal must be bracketed
// (RFC 3986) or the egress proxy cannot parse it and rejects the
// connection with "proxy request failed".
export function toSocketHostname(address: string): string {
  if (address.includes(':') && !address.startsWith('[')) return `[${address}]`;
  return address;
}

interface DnsAnswer { type: number; data: string }

async function resolveDnsType(host: string, type: 'A' | 'AAAA'): Promise<string[]> {
  const endpoint = 'https://cloudflare-dns.com/dns-query';
  const headers = { Accept: 'application/dns-json' };
  const response = await fetch(`${endpoint}?name=${encodeURIComponent(host)}&type=${type}`, {
    headers,
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error('Unable to verify the target DNS records');
  const responseUrl = new URL(response.url);
  if (responseUrl.origin !== 'https://cloudflare-dns.com'
    || !responseUrl.pathname.startsWith('/dns-query')
    || !response.headers.get('Content-Type')?.toLowerCase().startsWith('application/dns-json')) {
    throw new Error('Unexpected DNS resolver response');
  }
  const result = await response.json<{ Status: number; Answer?: DnsAnswer[] }>();
  if (result.Status !== 0 && result.Status !== 3) throw new Error('Unable to verify the target DNS records');
  if ((result.Answer?.length ?? 0) > 64) throw new Error('Target DNS response has too many records');
  const addresses: string[] = [];
  for (const answer of result.Answer ?? []) {
    if (answer.type === 1 && isIPv4(answer.data)) addresses.push(answer.data);
    if (answer.type === 28 && answer.data.includes(':')) {
      const normalized = normalizeIPv6(answer.data);
      if (!normalized.includes('%') && normalized.includes(':')) addresses.push(normalized);
    }
  }
  return addresses;
}

export async function resolvePublicAddresses(host: string, mode: 'strict' | 'best-effort' = 'strict'): Promise<string[]> {
  if (host.includes(':') || isIPv4(host)) return [host];
  const types = ['A', 'AAAA'] as const;
  const results = await Promise.allSettled(types.map((type) => resolveDnsType(host, type)));
  const addresses: string[] = [];
  for (const result of results) {
    if (result.status === 'rejected') {
      if (mode === 'strict') throw result.reason;
      continue;
    }
    addresses.push(...result.value);
  }
  return addresses;
}

export async function assertPublicTarget(host: string): Promise<string[]> {
  if (isPrivateAddress(host)) throw new Error('Private and reserved SSH targets are disabled');
  const addresses = await resolvePublicAddresses(host);
  if (addresses.length === 0) throw new Error('SSH target did not resolve to an address');
  for (const address of addresses) if (isPrivateAddress(address)) throw new Error('Target DNS resolves to a private or reserved address');
  const unique = [...new Set(addresses.map((address) => address.toLowerCase()))];
  if (unique.length > 16) throw new Error('SSH target resolves to too many addresses');
  return unique;
}
