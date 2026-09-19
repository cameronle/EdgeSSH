import assert from 'node:assert/strict';
import test from 'node:test';
import { createTicket } from '../src/backend/security.ts';
import {
  consumeStoredTicket,
  SESSION_TICKET_STORAGE_KEY,
  type StoredTicket,
} from '../src/backend/ticket-store.ts';
import type { SessionGrant } from '../src/types.ts';

class MemoryStorage {
  private readonly values = new Map<string, unknown>();

  async transaction<T>(callback: (transaction: MemoryStorage) => Promise<T>): Promise<T> {
    return callback(this);
  }

  async get<T>(key: string): Promise<T | undefined> {
    return this.values.get(key) as T | undefined;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async deleteAlarm(): Promise<void> {}

  async setAlarm(_time: number): Promise<void> {}
}

const IP = '203.0.113.7';
const GRANT: SessionGrant = {
  mode: 'saved',
  hostId: '123e4567-e89b-42d3-a456-426614174000',
};

async function storedTicket(storage: MemoryStorage): Promise<string> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const created = await createTicket(secret, IP);
  const stored: StoredTicket = {
    secret: Array.from(secret),
    expiresAt: created.expiresAt,
    ip: IP,
    grant: GRANT,
  };
  await storage.put(SESSION_TICKET_STORAGE_KEY, stored);
  secret.fill(0);
  return created.ticket;
}

test('a valid session ticket returns its grant exactly once', async () => {
  const storage = new MemoryStorage();
  const ticket = await storedTicket(storage);

  assert.deepEqual(await consumeStoredTicket(storage as unknown as DurableObjectStorage, ticket, IP), GRANT);
  assert.equal(await consumeStoredTicket(storage as unknown as DurableObjectStorage, ticket, IP), null);
  assert.equal(await storage.get(SESSION_TICKET_STORAGE_KEY), undefined);
});

test('an invalid ticket consumes the stored authorization and blocks a later replay', async () => {
  const storage = new MemoryStorage();
  const ticket = await storedTicket(storage);

  assert.equal(await consumeStoredTicket(storage as unknown as DurableObjectStorage, 'invalid-ticket', IP), null);
  assert.equal(await consumeStoredTicket(storage as unknown as DurableObjectStorage, ticket, IP), null);
  assert.equal(await storage.get(SESSION_TICKET_STORAGE_KEY), undefined);
});
