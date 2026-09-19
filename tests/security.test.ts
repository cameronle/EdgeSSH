import assert from 'node:assert/strict';
import test from 'node:test';
import { isPrivateAddress } from '../src/backend/security.ts';

test('rejects IPv4-compatible, mapped, and special-purpose IPv6 targets', () => {
  for (const address of [
    '::1',
    '::127.0.0.1',
    '0:0:0:0:0:0:7f00:1',
    '::ffff:127.0.0.1',
    '::ffff:169.254.169.254',
    '100::',
    '2001::1',
    '2001:db8::1',
    'fc00::1',
    'fe80::1',
    'ff02::1',
    '2002:7f00:1::1',
  ]) {
    assert.equal(isPrivateAddress(address), true, address);
  }
});

test('does not reject an ordinary public IPv6 address', () => {
  assert.equal(isPrivateAddress('2606:4700:4700::1111'), false);
});
