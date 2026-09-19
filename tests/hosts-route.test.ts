import assert from 'node:assert/strict';
import test from 'node:test';
import { base64, decryptHost, encryptHost } from '../src/accounts/crypto.ts';
import { hostsRoute } from '../src/accounts/hosts.ts';
import { APIError } from '../src/accounts/http.ts';
import type { HostPayload } from '../src/accounts/saved-connection.ts';
import type { Env } from '../src/types.ts';

interface FakeHostRow {
  id: string;
  account_id: string;
  encrypted_payload: string;
  updated_at: number;
}

class FakeStatement {
  private args: unknown[] = [];
  private readonly sql: string;
  private readonly rows: FakeHostRow[];
  private readonly statements: string[];

  constructor(sql: string, rows: FakeHostRow[], statements: string[]) {
    this.sql = sql;
    this.rows = rows;
    this.statements = statements;
  }

  bind(...args: unknown[]): this {
    this.args = args;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const [id, accountId] = this.args;
    const row = this.rows.find((item) => item.id === id && item.account_id === accountId);
    if (!row) return null;
    return {
      id: row.id,
      encrypted_payload: row.encrypted_payload,
      updated_at: row.updated_at,
    } as T;
  }

  async run(): Promise<D1Result<unknown>> {
    this.statements.push(this.sql);
    if (/SET\s+updated_at\s*=\s*\?/i.test(this.sql) && !/encrypted_payload/i.test(this.sql)) {
      const [updatedAt, id, accountId] = this.args;
      const row = this.rows.find((item) => item.id === id && item.account_id === accountId);
      if (row) row.updated_at = Number(updatedAt);
      return { meta: { changes: row ? 1 : 0 } } as D1Result<unknown>;
    }
    if (/SET\s+encrypted_payload\s*=\s*\?,\s*updated_at\s*=\s*\?/i.test(this.sql)) {
      const [encryptedPayload, updatedAt, id, accountId] = this.args;
      const row = this.rows.find((item) => item.id === id && item.account_id === accountId);
      if (row) {
        row.encrypted_payload = String(encryptedPayload);
        row.updated_at = Number(updatedAt);
      }
      return { meta: { changes: row ? 1 : 0 } } as D1Result<unknown>;
    }
    throw new Error(`Unexpected SQL: ${this.sql}`);
  }
}

function fakeEnv(rows: FakeHostRow[], key: string, statements: string[] = []): Env {
  return {
    DB: {
      prepare(sql: string) {
        return new FakeStatement(sql, rows, statements);
      },
    } as unknown as D1Database,
    ENCRYPTION_KEY: key,
  } as Env;
}

const ACCOUNT_ID = 'access-sub-a';
const HOST_ID = '123e4567-e89b-42d3-a456-426614174000';
const FINGERPRINT_A = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FINGERPRINT_B = 'SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

function hostPayload(): HostPayload {
  return {
    name: 'Puppets',
    group: '个人',
    host: '203.0.113.10',
    port: 20511,
    username: 'root',
    authMethod: 'password',
    password: 'stored-secret-password',
    initialCommand: '',
    termType: 'xterm-256color',
    encoding: 'utf-8',
    fingerprint: FINGERPRINT_A,
    location: {
      ip: '203.0.113.10',
      city: 'London',
      region: 'England',
      country: 'United Kingdom',
      countryCode: 'GB',
      latitude: 51.5072,
      longitude: -0.1276,
    },
    system: null,
  };
}

async function encryptedRow(key: string): Promise<FakeHostRow> {
  return {
    id: HOST_ID,
    account_id: ACCOUNT_ID,
    encrypted_payload: await encryptHost(hostPayload(), key, ACCOUNT_ID, HOST_ID),
    updated_at: 1_700_000_000_000,
  };
}

function jsonRequest(path: string, method: string, body?: unknown): Request {
  return new Request(`https://ssh.example.test${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test('legacy credentials endpoint fails closed with 410 before reading D1', async () => {
  const env = {
    DB: {
      prepare() {
        throw new Error('credentials compatibility handler must not read D1');
      },
    } as unknown as D1Database,
  } as Env;

  await assert.rejects(
    hostsRoute(jsonRequest(`/api/hosts/${HOST_ID}/credentials`, 'POST'), env, ACCOUNT_ID, `/api/hosts/${HOST_ID}/credentials`),
    (error: unknown) => error instanceof APIError
      && error.status === 410
      && error.message.includes('不再向浏览器返回'),
  );
});

test('connected endpoint updates only updated_at without decrypting or rewriting the payload', async () => {
  const statements: string[] = [];
  const row: FakeHostRow = {
    id: HOST_ID,
    account_id: ACCOUNT_ID,
    encrypted_payload: 'deliberately-not-decryptable',
    updated_at: 1,
  };
  const env = fakeEnv([row], 'invalid-key-is-safe-because-connected-must-not-decrypt', statements);

  const response = await hostsRoute(
    jsonRequest(`/api/hosts/${HOST_ID}/connected`, 'POST'),
    env,
    ACCOUNT_ID,
    `/api/hosts/${HOST_ID}/connected`,
  );
  const body = await response.json() as { ok: boolean; updatedAt: number };

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(row.updated_at, body.updatedAt);
  assert.equal(row.encrypted_payload, 'deliberately-not-decryptable');
  assert.equal(statements.length, 1);
  assert.match(statements[0], /^UPDATE hosts SET updated_at = \? WHERE id = \? AND account_id = \?$/);
});

test('fingerprint update without browser credentials preserves the stored password', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const row = await encryptedRow(key);
  const env = fakeEnv([row], key);
  const input = {
    name: 'Puppets',
    group: '个人',
    host: '203.0.113.10',
    port: 20511,
    username: 'root',
    authMethod: 'password',
    initialCommand: '',
    termType: 'xterm-256color',
    encoding: 'utf-8',
    fingerprint: FINGERPRINT_B,
  };

  const response = await hostsRoute(
    jsonRequest(`/api/hosts/${HOST_ID}`, 'PUT', input),
    env,
    ACCOUNT_ID,
    `/api/hosts/${HOST_ID}`,
  );
  const returned = await response.json() as { host: { fingerprint: string; hasCredential: boolean } };
  const stored = await decryptHost<HostPayload>(row.encrypted_payload, key, ACCOUNT_ID, HOST_ID);

  assert.equal(response.status, 200);
  assert.equal(returned.host.fingerprint, FINGERPRINT_B);
  assert.equal(returned.host.hasCredential, true);
  assert.equal(stored.fingerprint, FINGERPRINT_B);
  assert.equal(stored.password, 'stored-secret-password');
  assert.equal(stored.privateKey, undefined);
});

test('changing authentication method still requires a new credential', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const row = await encryptedRow(key);
  const originalCiphertext = row.encrypted_payload;
  const env = fakeEnv([row], key);
  const input = {
    name: 'Puppets',
    group: '个人',
    host: '203.0.113.10',
    port: 20511,
    username: 'root',
    authMethod: 'publickey',
    initialCommand: '',
    termType: 'xterm-256color',
    encoding: 'utf-8',
    fingerprint: FINGERPRINT_A,
  };

  await assert.rejects(
    hostsRoute(
      jsonRequest(`/api/hosts/${HOST_ID}`, 'PUT', input),
      env,
      ACCOUNT_ID,
      `/api/hosts/${HOST_ID}`,
    ),
    (error: unknown) => error instanceof APIError && error.status === 400,
  );
  assert.equal(row.encrypted_payload, originalCiphertext);
});
