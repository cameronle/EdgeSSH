import { savedConnectionConfig } from '../accounts/saved-connection.ts';
import {
  parseConnectMessage,
  parseSavedConnectMessage,
  type Env,
  type SessionGrant,
  type SSHConnectionConfig,
} from '../types.ts';

export async function connectionConfigForGrant(
  env: Env,
  accountId: string,
  grant: SessionGrant,
  message: unknown,
): Promise<SSHConnectionConfig> {
  if (grant.mode === 'manual') return parseConnectMessage(message);
  if (!grant.hostId) throw new Error('Saved host is unavailable');
  const start = parseSavedConnectMessage(message);
  return savedConnectionConfig(env, accountId, grant.hostId, start.cols, start.rows);
}
