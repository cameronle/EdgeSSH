import assert from 'node:assert/strict';
import test from 'node:test';
import { base64, encryptHost } from '../src/accounts/crypto.ts';
import {
  savedConnectionConfig,
  savedHostExists,
  type HostPayload,
} from '../src/accounts/saved-connection.ts';
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

  constructor(sql: string, rows: FakeHostRow[]) {
    this.sql = sql;
    this.rows = rows;
  }

  bind(...args: unknown[]): this {
    this.args = args;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const [id, accountId] = this.args;
    const row = this.rows.find((item) => item.id === id && item.account_id === accountId);
    if (!row) return null;
    if (/SELECT\s+1\s+AS\s+found/i.test(this.sql)) return { found: 1 } as T;
    return {
      id: row.id,
      encrypted_payload: row.encrypted_payload,
      updated_at: row.updated_at,
    } as T;
  }
}

function fakeEnv(rows: FakeHostRow[], key: string): Env {
  return {
    DB: {
      prepare(sql: string) {
        return new FakeStatement(sql, rows);
      },
    } as unknown as D1Database,
    ENCRYPTION_KEY: key,
  } as Env;
}

const ACCOUNT_A = 'access-sub-a';
const ACCOUNT_B = 'access-sub-b';
const HOST_ID = '123e4567-e89b-42d3-a456-426614174000';

function hostPayload(overrides: Partial<HostPayload> = {}): HostPayload {
  return {
    name: 'Puppets',
    group: '个人',
    host: '203.0.113.10',
    port: 20511,
    username: 'root',
    authMethod: 'password',
    password: 'stored-secret-password',
    initialCommand: 'tmux attach || tmux',
    termType: 'xterm-256color',
    encoding: 'utf-8',
    fingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    location: null,
    system: null,
    ...overrides,
  };
}

async function encryptedRow(key: string, payload = hostPayload()): Promise<FakeHostRow> {
  return {
    id: HOST_ID,
    account_id: ACCOUNT_A,
    encrypted_payload: await encryptHost(payload, key, ACCOUNT_A, HOST_ID),
    updated_at: Date.now(),
  };
}

test('savedHostExists scopes a saved host to the Access account', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const row = await encryptedRow(key);
  const env = fakeEnv([row], key);

  assert.equal(await savedHostExists(env, ACCOUNT_A, HOST_ID), true);
  assert.equal(await savedHostExists(env, ACCOUNT_B, HOST_ID), false);
});

test('savedConnectionConfig decrypts and validates a saved password connection server-side', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const env = fakeEnv([await encryptedRow(key)], key);

  const config = await savedConnectionConfig(env, ACCOUNT_A, HOST_ID, 132.9, 44.8);

  assert.deepEqual(config, {
    type: 'connect',
    host: '203.0.113.10',
    port: 20511,
    username: 'root',
    authMethod: 'password',
    password: 'stored-secret-password',
    privateKey: undefined,
    cols: 132,
    rows: 44,
    term: 'xterm-256color',
    expectedFingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  });
});

test('savedConnectionConfig supports a saved private key without exposing another credential type', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const privateKey = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----';
  const payload = hostPayload({
    authMethod: 'publickey',
    password: undefined,
    privateKey,
    fingerprint: '',
    termType: 'screen-256color',
  });
  const env = fakeEnv([await encryptedRow(key, payload)], key);

  const config = await savedConnectionConfig(env, ACCOUNT_A, HOST_ID, 120, 40);

  assert.equal(config.authMethod, 'publickey');
  assert.equal(config.privateKey, privateKey);
  assert.equal(config.password, undefined);
  assert.equal(config.expectedFingerprint, undefined);
  assert.equal(config.term, 'screen-256color');
});

test('savedConnectionConfig fails closed for another account or a missing host', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const env = fakeEnv([await encryptedRow(key)], key);

  await assert.rejects(
    savedConnectionConfig(env, ACCOUNT_B, HOST_ID, 120, 40),
    (error: unknown) => error instanceof Error && error.message === 'Saved host is unavailable',
  );
  await assert.rejects(
    savedConnectionConfig(env, ACCOUNT_A, '923e4567-e89b-42d3-a456-426614174000', 120, 40),
    (error: unknown) => error instanceof Error && error.message === 'Saved host is unavailable',
  );
});

test('savedConnectionConfig hides ciphertext and credential details when decryption fails', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const row = await encryptedRow(key);
  row.encrypted_payload = 'v1.invalid.invalid';
  const env = fakeEnv([row], key);

  await assert.rejects(
    savedConnectionConfig(env, ACCOUNT_A, HOST_ID, 120, 40),
    (error: unknown) => {
      assert.equal(error instanceof Error ? error.message : '', 'Saved host is unavailable');
      assert.equal(String(error).includes(row.encrypted_payload), false);
      assert.equal(String(error).includes('stored-secret-password'), false);
      return true;
    },
  );
});
