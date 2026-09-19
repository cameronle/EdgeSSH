import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseSavedConnectMessage,
  parseSessionRequest,
  type SavedConnectMessage,
  type SessionGrant,
} from '../src/types.ts';

const VALID_HOST_ID = '123e4567-e89b-42d3-a456-426614174000';

function expectSessionGrant(value: unknown, expected: SessionGrant): void {
  assert.deepEqual(parseSessionRequest(value), expected);
}

test('parseSessionRequest treats an empty object as a manual session', () => {
  expectSessionGrant({}, { mode: 'manual' });
});

test('parseSessionRequest accepts only a v4 UUID hostId for a saved session', () => {
  expectSessionGrant({ hostId: VALID_HOST_ID }, { mode: 'saved', hostId: VALID_HOST_ID });
});

test('parseSessionRequest rejects non-object values', () => {
  for (const value of [null, 'manual', [], 42, true]) {
    assert.throws(() => parseSessionRequest(value), /Invalid session request/);
  }
});

test('parseSessionRequest rejects invalid or non-v4 host IDs', () => {
  for (const hostId of [
    '',
    42,
    'not-a-uuid',
    '123e4567-e89b-12d3-a456-426614174000',
    '123e4567-e89b-42d3-7456-426614174000',
  ]) {
    assert.throws(() => parseSessionRequest({ hostId }), /Invalid session request/);
  }
});

test('parseSessionRequest rejects every field except hostId', () => {
  for (const value of [
    { extra: true },
    { password: 'secret' },
    { privateKey: 'key' },
    { hostId: VALID_HOST_ID, extra: true },
    { hostId: VALID_HOST_ID, password: 'secret' },
    { hostId: VALID_HOST_ID, privateKey: 'key' },
  ]) {
    assert.throws(() => parseSessionRequest(value), /Invalid session request/);
  }
});

function expectSavedConnectMessage(value: unknown, expected: SavedConnectMessage): void {
  assert.deepEqual(parseSavedConnectMessage(value), expected);
}

test('parseSavedConnectMessage accepts and normalizes a saved connection size', () => {
  expectSavedConnectMessage(
    { type: 'connect_saved', cols: 120.9, rows: 40.8 },
    { type: 'connect_saved', cols: 120, rows: 40 },
  );
});

test('parseSavedConnectMessage rejects non-object values and the wrong message type', () => {
  for (const value of [null, 'connect_saved', [], 42, true, {}, { type: 'connect' }]) {
    assert.throws(() => parseSavedConnectMessage(value), /Invalid saved connect message/);
  }
});

test('parseSavedConnectMessage rejects invalid terminal sizes', () => {
  for (const value of [
    { type: 'connect_saved', rows: 40 },
    { type: 'connect_saved', cols: 120 },
    { type: 'connect_saved', cols: 9, rows: 40 },
    { type: 'connect_saved', cols: 120, rows: 4 },
    { type: 'connect_saved', cols: 1001, rows: 40 },
    { type: 'connect_saved', cols: 120, rows: 1001 },
    { type: 'connect_saved', cols: '120', rows: 40 },
    { type: 'connect_saved', cols: 120, rows: Number.NaN },
  ]) {
    assert.throws(() => parseSavedConnectMessage(value), /Invalid terminal size/);
  }
});

test('parseSavedConnectMessage rejects every field except type, cols, and rows', () => {
  for (const field of ['hostId', 'host', 'password', 'privateKey', 'extra']) {
    assert.throws(
      () => parseSavedConnectMessage({ type: 'connect_saved', cols: 120, rows: 40, [field]: 'forbidden' }),
      /Unsupported saved connection field/,
    );
  }
});
