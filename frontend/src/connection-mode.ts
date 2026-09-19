export type AuthMethod = 'password' | 'publickey';

export interface SavedReconnectParams {
  mode: 'saved';
  hostId: string;
  encoding: string;
  initialCommand: string;
  label: string;
  pinnedKey?: string;
}

export interface ManualReconnectParams {
  mode: 'manual';
  host: string;
  port: number;
  username: string;
  authMethod: AuthMethod;
  password?: string;
  privateKey?: string;
  pinnedKey?: string;
  term: string;
  encoding: string;
  initialCommand: string;
  label: string;
}

export type ReconnectParams = SavedReconnectParams | ManualReconnectParams;

interface SavedConnectFrame {
  type: 'connect_saved';
  cols: number;
  rows: number;
}

interface ManualConnectFrame {
  type: 'connect';
  host: string;
  port: number;
  username: string;
  authMethod: AuthMethod;
  password?: string;
  privateKey?: string;
  cols: number;
  rows: number;
  term: string;
  expectedFingerprint?: string;
}

export type InitialConnectFrame = SavedConnectFrame | ManualConnectFrame;

export type CredentialSelectionError = 'required' | 'too_large' | 'unsupported_format';

export function validateCredentialSelection(
  mode: ReconnectParams['mode'],
  authMethod: AuthMethod,
  privateKey: string,
  maxKeyBytes: number,
): CredentialSelectionError | null {
  if (mode === 'saved' || authMethod !== 'publickey') return null;
  const key = privateKey.trim();
  if (!key) return 'required';
  if (new TextEncoder().encode(key).length > maxKeyBytes) return 'too_large';
  if (!key.includes('BEGIN OPENSSH PRIVATE KEY')) return 'unsupported_format';
  return null;
}

function terminalSize(cols: number, rows: number): { cols: number; rows: number } {
  if (!Number.isFinite(cols) || !Number.isFinite(rows)) throw new Error('Invalid terminal size');
  const size = { cols: Math.floor(cols), rows: Math.floor(rows) };
  if (size.cols < 10 || size.cols > 1000 || size.rows < 5 || size.rows > 1000) {
    throw new Error('Invalid terminal size');
  }
  return size;
}

export function sessionRequestBody(params: ReconnectParams): Record<string, string> {
  return params.mode === 'saved' ? { hostId: params.hostId } : {};
}

export function buildInitialConnectFrame(
  params: ReconnectParams,
  cols: number,
  rows: number,
): InitialConnectFrame {
  const size = terminalSize(cols, rows);
  if (params.mode === 'saved') return { type: 'connect_saved', ...size };

  const frame: ManualConnectFrame = {
    type: 'connect',
    host: params.host,
    port: params.port,
    username: params.username,
    authMethod: params.authMethod,
    cols: size.cols,
    rows: size.rows,
    term: params.term,
  };
  if (params.authMethod === 'password') frame.password = params.password;
  else frame.privateKey = params.privateKey;
  if (params.pinnedKey) frame.expectedFingerprint = params.pinnedKey;
  return frame;
}
