import assert from 'node:assert/strict';
import test from 'node:test';
import { base64, encryptHost } from '../src/accounts/crypto.ts';
import { connectionConfigForGrant } from '../src/backend/connection-grant.ts';
import type { HostPayload } from '../src/accounts/saved-connection.ts';
import type { Env, SessionGrant } from '../src/types.ts';

interface FakeHostRow {
  id: string;
  account_id: string;
  encrypted_payload: string;
}

class FakeStatement {
  private args: unknown[] = [];
  private readonly rows: FakeHostRow[];

  constructor(rows: FakeHostRow[]) {
    this.rows = rows;
  }

  bind(...args: unknown[]): this {
    this.args = args;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const [id, accountId] = this.args;
    const row = this.rows.find((item) => item.id === id && item.account_id === accountId);
    return row ? { encrypted_payload: row.encrypted_payload } as T : null;
  }
}

function fakeEnv(rows: FakeHostRow[], key: string): Env {
  return {
    DB: { prepare: () => new FakeStatement(rows) } as unknown as D1Database,
    ENCRYPTION_KEY: key,
  } as Env;
}

const HOST_ID = '123e4567-e89b-42d3-a456-426614174000';
const ACCOUNT_ID = 'access-sub-a';

function manualMessage() {
  return {
    type: 'connect',
    host: '1.1.1.1',
    port: 22,
    username: 'root',
    authMethod: 'password',
    password: 'manual-password',
    cols: 120,
    rows: 40,
    term: 'xterm-256color',
  };
}

async function savedFixture(): Promise<{ env: Env; grant: SessionGrant }> {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const payload: HostPayload = {
    name: 'Saved VPS',
    group: '个人',
    host: '8.8.8.8',
    port: 20511,
    username: 'root',
    authMethod: 'password',
    password: 'saved-password-never-sent-by-browser',
    initialCommand: '',
    termType: 'xterm-256color',
    encoding: 'utf-8',
    fingerprint: '',
    location: null,
  };
  return {
    env: fakeEnv([{
      id: HOST_ID,
      account_id: ACCOUNT_ID,
      encrypted_payload: await encryptHost(payload, key, ACCOUNT_ID, HOST_ID),
    }], key),
    grant: { mode: 'saved', hostId: HOST_ID },
  };
}

test('manual grant accepts only the existing full connect message', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const env = fakeEnv([], key);
  const config = await connectionConfigForGrant(env, ACCOUNT_ID, { mode: 'manual' }, manualMessage());

  assert.equal(config.password, 'manual-password');
  assert.equal(config.host, '1.1.1.1');
  await assert.rejects(
    connectionConfigForGrant(env, ACCOUNT_ID, { mode: 'manual' }, { type: 'connect_saved', cols: 120, rows: 40 }),
  );
});

test('saved grant loads credentials server-side from its bound host ID', async () => {
  const { env, grant } = await savedFixture();
  const browserFrame = { type: 'connect_saved', cols: 133.7, rows: 41.9 };
  const config = await connectionConfigForGrant(env, ACCOUNT_ID, grant, browserFrame);

  assert.equal(config.host, '8.8.8.8');
  assert.equal(config.password, 'saved-password-never-sent-by-browser');
  assert.equal(config.cols, 133);
  assert.equal(config.rows, 41);
  assert.equal(JSON.stringify(browserFrame).includes('saved-password-never-sent-by-browser'), false);
});

test('saved grant rejects a browser-supplied full connect frame and credential injection', async () => {
  const { env, grant } = await savedFixture();

  await assert.rejects(connectionConfigForGrant(env, ACCOUNT_ID, grant, manualMessage()));
  await assert.rejects(connectionConfigForGrant(env, ACCOUNT_ID, grant, {
    type: 'connect_saved',
    cols: 120,
    rows: 40,
    password: 'injected',
  }));
});

test('saved grant fails closed when the host is not owned by the Access account', async () => {
  const { env, grant } = await savedFixture();
  await assert.rejects(
    connectionConfigForGrant(env, 'different-access-sub', grant, { type: 'connect_saved', cols: 120, rows: 40 }),
    (error: unknown) => error instanceof Error && error.message === 'Saved host is unavailable',
  );
});

test('saved grant fails closed when the host is deleted after ticket issuance', async () => {
  const key = base64(crypto.getRandomValues(new Uint8Array(32)));
  const env = fakeEnv([], key);
  await assert.rejects(
    connectionConfigForGrant(
      env,
      ACCOUNT_ID,
      { mode: 'saved', hostId: HOST_ID },
      { type: 'connect_saved', cols: 120, rows: 40 },
    ),
    (error: unknown) => error instanceof Error && error.message === 'Saved host is unavailable',
  );
});
