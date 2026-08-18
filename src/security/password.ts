/**
 * Password hashing utilities (Argon2id, with bcrypt kept for verification only)
 *
 * New hashes are Argon2id. Existing bcrypt hashes stay verifiable and are
 * upgraded lazily: verifyPassword reports `needsRehash`, and the signin path
 * rehashes on the next successful login. There is no bulk migration because we
 * do not hold plaintext — the only moment a password is available to rehash is
 * the moment its owner types it.
 *
 * To track the migration:
 *   SELECT COUNT(*) FROM users WHERE password_hash LIKE '$2%';
 * When that reaches 0, the bcryptjs dependency can be dropped from this file.
 * (bcryptjs is still used elsewhere to hash OTPs — see src/security/jwt.ts.)
 */

import { hash as argon2Hash, verify as argon2Verify, Algorithm } from '@node-rs/argon2';
import bcrypt from 'bcryptjs';

/**
 * OWASP-recommended Argon2id parameters. These are also the library defaults,
 * but they are stated explicitly: a silent upstream default change would alter
 * the security posture of every new password without any diff here to review.
 *
 * Changing memoryCost/timeCost/parallelism does NOT invalidate existing hashes —
 * the parameters are encoded in the hash string, so old hashes keep verifying
 * with the parameters they were created under.
 */
const ARGON2_OPTIONS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19456, // 19 MiB per thread
  timeCost: 2,
  parallelism: 1,
} as const;

/** bcrypt hashes start with $2a$ / $2b$ / $2y$; Argon2 hashes start with $argon2. */
function isBcryptHash(hash: string): boolean {
  return /^\$2[aby]?\$/.test(hash);
}

/**
 * Hash a plain-text password with Argon2id.
 * Always await this — it is deliberately expensive (~50-100ms).
 *
 * Callers must keep enforcing the 72-character cap in src/schemas/auth.schemas.ts.
 * Argon2 itself has no such limit, but the cap is shown to users by the website's
 * own validator, so relaxing it here would desync the two.
 */
export async function hashPassword(plain: string): Promise<string> {
  return argon2Hash(plain, ARGON2_OPTIONS);
}

export interface PasswordVerification {
  /** True only if the password matches the stored hash. */
  valid: boolean;
  /**
   * True when the stored hash uses a superseded scheme (bcrypt) and should be
   * replaced with an Argon2id hash. Only meaningful when `valid` is true —
   * never rehash off a failed attempt, that would let an attacker overwrite a
   * victim's hash with their own guess.
   */
  needsRehash: boolean;
}

/**
 * Verify a plain-text password against a stored hash of either scheme.
 *
 * Never throws: a malformed or truncated hash in the database is a data problem,
 * not a reason to 500 a login. It returns `valid: false`, which the caller maps
 * to INVALID_CREDENTIALS like any other failure.
 */
export async function verifyPassword(plain: string, hash: string): Promise<PasswordVerification> {
  try {
    if (isBcryptHash(hash)) {
      // bcrypt silently truncates at 72 bytes. That is the behaviour these
      // hashes were created under, so verification must keep matching it —
      // do not "fix" it here or every long password stops verifying.
      const valid = await bcrypt.compare(plain, hash);
      return { valid, needsRehash: valid };
    }

    // NOTE argument order: argon2Verify(hash, password) — the reverse of
    // bcrypt.compare(password, hash). Inverting these fails open-ish in
    // confusing ways, so it is spelled out rather than passed positionally
    // from a shared variable.
    const valid = await argon2Verify(hash, plain, ARGON2_OPTIONS);
    return { valid, needsRehash: false };
  } catch {
    return { valid: false, needsRehash: false };
  }
}
