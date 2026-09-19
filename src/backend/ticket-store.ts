import { verifyTicket } from './security.ts';
import type { SessionGrant } from '../types.ts';

export const SESSION_TICKET_STORAGE_KEY = 'session-ticket';

export interface StoredTicket {
  secret: number[];
  expiresAt: number;
  ip: string;
  grant: SessionGrant;
}

export async function consumeStoredTicket(
  storage: DurableObjectStorage,
  ticket: string,
  ip: string,
): Promise<SessionGrant | null> {
  return storage.transaction(async (transaction) => {
    const stored = await transaction.get<StoredTicket>(SESSION_TICKET_STORAGE_KEY);
    if (!stored) return null;

    // A presented ticket is one-shot even when malformed. Delete the grant
    // before cryptographic verification so concurrent or later replays fail.
    await transaction.delete(SESSION_TICKET_STORAGE_KEY);
    await transaction.deleteAlarm();
    await transaction.setAlarm(Date.now() + 7 * 86400_000);

    if (stored.expiresAt < Date.now() || stored.secret.length !== 32 || !stored.grant) return null;
    const secret = new Uint8Array(stored.secret);
    try {
      return await verifyTicket(secret, ticket, ip) ? stored.grant : null;
    } finally {
      secret.fill(0);
    }
  });
}
