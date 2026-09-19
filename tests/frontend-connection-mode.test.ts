import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildInitialConnectFrame,
  sessionRequestBody,
  validateCredentialSelection,
  type ReconnectParams,
} from '../frontend/src/connection-mode.ts';

const saved: ReconnectParams = {
  mode: 'saved',
  hostId: '123e4567-e89b-42d3-a456-426614174000',
  encoding: 'utf-8',
  initialCommand: '',
  label: 'root@example.com:22',
};

const manual: ReconnectParams = {
  mode: 'manual',
  host: 'example.com',
  port: 22,
  username: 'root',
  authMethod: 'password',
  password: 'manual-secret',
  term: 'xterm-256color',
  encoding: 'utf-8',
  initialCommand: '',
  label: 'root@example.com:22',
};

test('saved mode session request contains only the bound host ID', () => {
  assert.deepEqual(sessionRequestBody(saved), { hostId: saved.hostId });
});

test('saved mode WebSocket frame contains terminal size and no target or credentials', () => {
  const frame = buildInitialConnectFrame(saved, 120.9, 40.8);
  assert.deepEqual(frame, { type: 'connect_saved', cols: 120, rows: 40 });
  const serialized = JSON.stringify(frame);
  for (const forbidden of ['hostId', 'host', 'username', 'password', 'privateKey', 'manual-secret']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});

test('manual mode session request remains empty and its frame carries the current input credential', () => {
  assert.deepEqual(sessionRequestBody(manual), {});
  assert.deepEqual(buildInitialConnectFrame(manual, 120, 40), {
    type: 'connect',
    host: 'example.com',
    port: 22,
    username: 'root',
    authMethod: 'password',
    password: 'manual-secret',
    cols: 120,
    rows: 40,
    term: 'xterm-256color',
  });
});

test('manual public-key mode emits only the private key credential', () => {
  const keyMode: ReconnectParams = {
    ...manual,
    authMethod: 'publickey',
    password: undefined,
    privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----',
  };
  const frame = buildInitialConnectFrame(keyMode, 120, 40) as Record<string, unknown>;
  assert.equal(frame.password, undefined);
  assert.equal(typeof frame.privateKey, 'string');
});

test('saved public-key mode does not require the private key in the browser', () => {
  assert.equal(validateCredentialSelection('saved', 'publickey', '', 64 * 1024), null);
});

test('manual public-key mode still validates the browser private key', () => {
  assert.equal(validateCredentialSelection('manual', 'publickey', '', 64 * 1024), 'required');
  assert.equal(validateCredentialSelection('manual', 'publickey', 'not-a-key', 64 * 1024), 'unsupported_format');
  assert.equal(validateCredentialSelection(
    'manual',
    'publickey',
    `-----BEGIN OPENSSH PRIVATE KEY-----\n${'a'.repeat(70_000)}`,
    64 * 1024,
  ), 'too_large');
});
