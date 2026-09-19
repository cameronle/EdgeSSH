import { parseSessionRequest, type Env } from '../types.ts';
import { jsonError, secureResponse } from '../http-security.ts';
import { readJSON } from './http.ts';
import { savedHostExists } from './saved-connection.ts';

export function clientAddress(request: Request): string {
  const value = request.headers.get('CF-Connecting-IP') ?? 'local';
  return /^[0-9A-Fa-f:.]{2,64}$/.test(value) ? value.toLowerCase() : 'unknown';
}

export async function sessionTicket(request: Request, env: Env, accountId: string): Promise<Response> {
  const body = await readJSON(request, 8192);
  let grant;
  try { grant = parseSessionRequest(body); }
  catch { return jsonError('Invalid session request', 400); }
  if (grant.mode === 'saved' && !await savedHostExists(env, accountId, grant.hostId!)) {
    return jsonError('Saved host not found', 404);
  }
  const id = env.SSH_SESSIONS.newUniqueId();
  const stub = env.SSH_SESSIONS.get(id);
  const response = await stub.fetch(new Request('https://session.internal/ticket', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-client-ip': clientAddress(request),
      'x-account-id': accountId,
    },
    body: JSON.stringify(grant.mode === 'saved' ? { hostId: grant.hostId } : {}),
  }));
  if (!response.ok) return jsonError('Unable to create a session ticket', 503);
  const ticket = await response.json<{ ticket: string; expiresAt: number }>();
  return secureResponse(Response.json(
    { ...ticket, sessionId: id.toString(), mode: grant.mode },
    { headers: { 'Cache-Control': 'no-store' } },
  ));
}
