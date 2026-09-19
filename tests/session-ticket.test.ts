import assert from 'node:assert/strict';
import test from 'node:test';
import { APIError } from '../src/accounts/http.ts';
import { sessionTicket } from '../src/accounts/session-ticket.ts';
import type { Env } from '../src/types.ts';

interface SavedHost {
  id: string;
  accountId: string;
}

class HostExistsStatement {
  private args: unknown[] = [];
  private readonly hosts: SavedHost[];

  constructor(hosts: SavedHost[]) {
    this.hosts = hosts;
  }

  bind(...args: unknown[]): this {
    this.args = args;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const [id, accountId] = this.args;
    return this.hosts.some((host) => host.id === id && host.accountId === accountId)
      ? { found: 1 } as T
      : null;
  }
}

function fakeEnv(hosts: SavedHost[]) {
  const internalRequests: Request[] = [];
  let uniqueIds = 0;
  const env = {
    DB: {
      prepare() {
        return new HostExistsStatement(hosts);
      },
    } as unknown as D1Database,
    SSH_SESSIONS: {
      newUniqueId() {
        uniqueIds += 1;
        return { toString: () => `session-${uniqueIds}` };
      },
      get() {
        return {
          async fetch(request: Request) {
            internalRequests.push(request);
            return Response.json({ ticket: 'one-time-ticket', expiresAt: 1_900_000_000_000 });
          },
        };
      },
    } as unknown as DurableObjectNamespace,
  } as Env;
  return { env, internalRequests, getUniqueIds: () => uniqueIds };
}

const HOST_ID = '123e4567-e89b-42d3-a456-426614174000';
const ACCOUNT_A = 'access-sub-a';
const ACCOUNT_B = 'access-sub-b';

function request(body: unknown): Request {
  return new Request('https://ssh.example.test/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.7' },
    body: JSON.stringify(body),
  });
}

test('saved session refuses another account host ID before creating a Durable Object', async () => {
  const fixture = fakeEnv([{ id: HOST_ID, accountId: ACCOUNT_A }]);

  const response = await sessionTicket(request({ hostId: HOST_ID }), fixture.env, ACCOUNT_B);
  const body = await response.json() as { error: string };

  assert.equal(response.status, 404);
  assert.equal(body.error, 'Saved host not found');
  assert.equal(fixture.getUniqueIds(), 0);
  assert.equal(fixture.internalRequests.length, 0);
});

test('saved session response and internal grant contain no credentials or encrypted payload', async () => {
  const fixture = fakeEnv([{ id: HOST_ID, accountId: ACCOUNT_A }]);

  const response = await sessionTicket(request({ hostId: HOST_ID }), fixture.env, ACCOUNT_A);
  const body = await response.json() as Record<string, unknown>;
  const internalBody = await fixture.internalRequests[0].clone().json() as Record<string, unknown>;

  assert.equal(response.status, 200);
  assert.deepEqual(Object.keys(body).sort(), ['expiresAt', 'mode', 'sessionId', 'ticket']);
  assert.equal(body.mode, 'saved');
  assert.deepEqual(internalBody, { hostId: HOST_ID });
  const serialized = JSON.stringify({ body, internalBody });
  for (const forbidden of ['password', 'privateKey', 'encrypted_payload', 'ciphertext']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});

test('session request larger than 8192 bytes is rejected without Content-Length before creating a Durable Object', async () => {
  const fixture = fakeEnv([]);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(JSON.stringify({ padding: 'x'.repeat(9000) })));
      controller.close();
    },
  });
  const oversized = new Request('https://ssh.example.test/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: stream,
    duplex: 'half',
  } as RequestInit & { duplex: 'half' });
  assert.equal(oversized.headers.has('Content-Length'), false);

  await assert.rejects(
    sessionTicket(oversized, fixture.env, ACCOUNT_A),
    (error: unknown) => error instanceof APIError && error.status === 413,
  );
  assert.equal(fixture.getUniqueIds(), 0);
});
