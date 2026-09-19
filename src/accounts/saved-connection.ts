import { decryptHost } from './crypto.ts';
import { parseConnectMessage, type Env, type SSHConnectionConfig } from '../types.ts';
import type { HostLocation } from './location.ts';
import type { SystemInfo } from '../backend/system-info.ts';

export interface HostPayload {
  name: string;
  group: string;
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'publickey';
  password?: string;
  privateKey?: string;
  initialCommand: string;
  termType: string;
  encoding: string;
  fingerprint: string;
  location: HostLocation | null;
  locationCheckedAt?: number;
  system?: SystemInfo | null;
}

interface SavedHostRow {
  encrypted_payload: string;
}

const SAVED_HOST_UNAVAILABLE = 'Saved host is unavailable';

export async function savedHostExists(env: Env, accountId: string, hostId: string): Promise<boolean> {
  const row = await env.DB.prepare('SELECT 1 AS found FROM hosts WHERE id = ? AND account_id = ?')
    .bind(hostId, accountId)
    .first<{ found: number }>();
  return row?.found === 1;
}

export async function savedConnectionConfig(
  env: Env,
  accountId: string,
  hostId: string,
  cols: number,
  rows: number,
): Promise<SSHConnectionConfig> {
  try {
    const row = await env.DB.prepare('SELECT encrypted_payload FROM hosts WHERE id = ? AND account_id = ?')
      .bind(hostId, accountId)
      .first<SavedHostRow>();
    if (!row) throw new Error(SAVED_HOST_UNAVAILABLE);

    const payload = await decryptHost<HostPayload>(row.encrypted_payload, env.ENCRYPTION_KEY, accountId, hostId);
    return parseConnectMessage({
      type: 'connect',
      host: payload.host,
      port: payload.port,
      username: payload.username,
      authMethod: payload.authMethod,
      password: payload.password,
      privateKey: payload.privateKey,
      cols,
      rows,
      term: payload.termType,
      expectedFingerprint: payload.fingerprint || undefined,
    });
  } catch {
    throw new Error(SAVED_HOST_UNAVAILABLE);
  }
}
