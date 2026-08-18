/**
 * Password hashing — Argon2id with lazy bcrypt migration.
 *
 * No DB required: this is pure crypto. The one case that actually matters is
 * the migration path, because it is the only way an existing user's hash gets
 * replaced, and getting `needsRehash` wrong either strands every legacy hash
 * forever or lets a failed guess trigger a rehash.
 */

import { describe, it, expect } from 'vitest';
import bcrypt from 'bcryptjs';
import { hashPassword, verifyPassword } from './password.js';

const PASSWORD = 'correct horse battery staple';

describe('hashPassword', () => {
  it('produces an Argon2id hash', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(hash.startsWith('$argon2id$')).toBe(true);
  });

  it('salts — the same password hashes differently every time', async () => {
    expect(await hashPassword(PASSWORD)).not.toBe(await hashPassword(PASSWORD));
  });
});

describe('verifyPassword — Argon2 hashes', () => {
  it('accepts the correct password and does not ask for a rehash', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(await verifyPassword(PASSWORD, hash)).toEqual({ valid: true, needsRehash: false });
  });

  it('rejects the wrong password', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(await verifyPassword('wrong', hash)).toEqual({ valid: false, needsRehash: false });
  });
});

describe('verifyPassword — legacy bcrypt hashes', () => {
  it('accepts the correct password AND flags it for rehash', async () => {
    const legacy = await bcrypt.hash(PASSWORD, 10);
    expect(await verifyPassword(PASSWORD, legacy)).toEqual({ valid: true, needsRehash: true });
  });

  it('does NOT flag a rehash when the password was wrong', async () => {
    // Rehashing on a failed attempt would let an attacker overwrite a victim's
    // stored hash with a hash of the attacker's guess.
    const legacy = await bcrypt.hash(PASSWORD, 10);
    expect(await verifyPassword('wrong', legacy)).toEqual({ valid: false, needsRehash: false });
  });

  it('round-trips: a rehashed legacy password verifies under Argon2', async () => {
    const legacy = await bcrypt.hash(PASSWORD, 10);
    const { valid, needsRehash } = await verifyPassword(PASSWORD, legacy);
    expect(valid && needsRehash).toBe(true);

    const upgraded = await hashPassword(PASSWORD);
    expect(upgraded.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(PASSWORD, upgraded)).toEqual({ valid: true, needsRehash: false });
  });
});

describe('verifyPassword — malformed input', () => {
  // A corrupt hash in the DB is a data problem, not a reason to 500 a login.
  it.each([
    ['empty string', ''],
    ['not a hash', 'plain-text-oops'],
    ['truncated argon2', '$argon2id$v=19$m=19456,t=2,p=1$abc'],
    ['truncated bcrypt', '$2b$12$tooshort'],
  ])('returns valid:false for %s instead of throwing', async (_label, hash) => {
    expect(await verifyPassword(PASSWORD, hash)).toEqual({ valid: false, needsRehash: false });
  });
});
