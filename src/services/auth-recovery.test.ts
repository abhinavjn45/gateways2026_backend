/**
 * Signup / signin recovery and disclosure guarantees.
 *
 * These cover the failure that stranded real accounts in this database: an OTP
 * that could not be delivered produced an account that could neither sign in
 * (unverified) nor be recreated (EMAIL_TAKEN). Runs against a real MySQL
 * instance like the rest of the suite.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq, sql } from 'drizzle-orm';
import { v7 as uuidv7 } from 'uuid';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app.js';
import { getAppDb } from '../db/index.js';
import { users, accounts } from '../db/schema/auth.js';
import { deleteTestUser } from '../test-helpers/db.js';
import { hashPassword } from '../security/password.js';

const db = getAppDb();
const PASSWORD = 'hunter2hunter2';
let app: FastifyInstance;
const cleanup: string[] = [];

function freshEmail(tag: string) {
  return `recovery-${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
}

async function signup(email: string, password = PASSWORD) {
  return app.inject({
    method: 'POST',
    url: '/api/v1/auth/signup',
    payload: { email, password, username: `U${Math.random().toString(36).slice(2, 10)}` },
  });
}

async function signin(email: string, password = PASSWORD) {
  return app.inject({
    method: 'POST',
    url: '/api/v1/auth/signin',
    payload: { email, password },
  });
}

async function trackByEmail(email: string) {
  const row = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  if (row[0]) cleanup.push(row[0].id);
  return row[0]?.id;
}

beforeAll(async () => {
  ({ app } = await buildApp());
  await app.ready();
});

afterAll(async () => {
  for (const id of cleanup) await deleteTestUser(db, id).catch(() => {});
  await app.close();
});

describe('signup with verification disabled', () => {
  it('creates a verified account and signs the user in immediately', async () => {
    const email = freshEmail('active');
    const res = await signup(email);
    await trackByEmail(email);

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.status).toBe('ACTIVE');

    // The session must arrive with this response, not a later round-trip.
    const cookies = res.headers['set-cookie'];
    expect(String(cookies)).toContain('__session=');

    // And the account must be verified, or signin would refuse it.
    const [row] = await db
      .select({ emailVerified: users.emailVerified })
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    expect(row.emailVerified).not.toBeNull();
  });

  it('lets the new account sign in right away — the original bug', async () => {
    const email = freshEmail('signin');
    await signup(email);
    await trackByEmail(email);
    expect((await signin(email)).statusCode).toBe(200);
  });

  it('still refuses a duplicate address', async () => {
    const email = freshEmail('dupe');
    await signup(email);
    await trackByEmail(email);

    const second = await signup(email);
    expect(second.statusCode).toBe(409);
    expect(second.json().error.code).toBe('EMAIL_TAKEN');
  });
});

describe('user enumeration', () => {
  it('answers identically for a wrong password and an unknown address', async () => {
    const email = freshEmail('enum');
    await signup(email);
    await trackByEmail(email);

    const wrongPassword = await signin(email, 'definitely-not-the-password');
    const unknownAddress = await signin(freshEmail('ghost'), 'definitely-not-the-password');

    expect(wrongPassword.statusCode).toBe(unknownAddress.statusCode);
    expect(wrongPassword.statusCode).toBe(401);

    // correlationId is per-request by design; everything else must match.
    const strip = (r: typeof wrongPassword) => {
      const { correlationId, ...rest } = r.json().error;
      void correlationId;
      return rest;
    };
    expect(strip(wrongPassword)).toEqual(strip(unknownAddress));
  });
});

describe('OAuth accounts are never password-prompted', () => {
  it('refuses to graft a password onto a Google identity', async () => {
    const email = freshEmail('oauth');
    const userId = uuidv7();
    cleanup.push(userId);

    // A Google-created account: no password hash, verified by Google.
    await db.insert(users).values({
      id: userId,
      email,
      passwordHash: null,
      status: 'ACTIVE',
      emailVerified: sql`now()`,
    });
    await db.insert(accounts).values({
      id: uuidv7(),
      userId,
      type: 'oauth',
      provider: 'google',
      providerAccountId: `google-${userId}`,
    });

    const res = await signup(email);
    expect(res.statusCode).toBe(409);
    expect(res.json().error.code).toBe('OAUTH_ACCOUNT');
  });

  it('does not reveal the account is OAuth-backed via signin', async () => {
    const email = freshEmail('oauth-signin');
    const userId = uuidv7();
    cleanup.push(userId);
    await db.insert(users).values({
      id: userId,
      email,
      passwordHash: null,
      status: 'ACTIVE',
      emailVerified: sql`now()`,
    });

    // Must be the generic credential failure — OAUTH_ACCOUNT here would confirm
    // the address exists to anyone probing.
    const res = await signin(email);
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe('INVALID_CREDENTIALS');
  });
});

describe('legacy bcrypt hashes', () => {
  it('signs in and transparently upgrades the stored hash to Argon2', async () => {
    const email = freshEmail('bcrypt');
    await signup(email);
    const userId = await trackByEmail(email);

    // Rewind this account to a bcrypt hash, as pre-migration rows are.
    const bcrypt = (await import('bcryptjs')).default;
    await db
      .update(users)
      .set({ passwordHash: await bcrypt.hash(PASSWORD, 10) })
      .where(eq(users.id, userId!));

    expect((await signin(email)).statusCode).toBe(200);

    // The rehash is deliberately off the response path (fire-and-forget, so a
    // slow write never delays the login response) — poll instead of a fixed
    // sleep, since a single wait races Argon2's ~50-100ms cost against however
    // busy the machine running the full suite happens to be.
    let upgraded = false;
    for (let attempt = 0; attempt < 20 && !upgraded; attempt++) {
      await new Promise((r) => setTimeout(r, 250));
      const [row] = await db
        .select({ passwordHash: users.passwordHash })
        .from(users)
        .where(eq(users.id, userId!))
        .limit(1);
      upgraded = Boolean(row.passwordHash?.startsWith('$argon2'));
    }
    expect(upgraded).toBe(true);
  });
});

describe('suspended accounts', () => {
  it('rejects a banned user with the correct password', async () => {
    const email = freshEmail('banned');
    await signup(email);
    const userId = await trackByEmail(email);
    await db.update(users).set({ status: 'BANNED' }).where(eq(users.id, userId!));

    const res = await signin(email);
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('FORBIDDEN');
  });
});

describe('console door', () => {
  it('refuses an account with no staff role', async () => {
    const email = freshEmail('nostaff');
    await signup(email);
    await trackByEmail(email);

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/admin/auth/signin',
      headers: { 'x-auth-transport': 'bearer' },
      payload: { email, password: PASSWORD },
    });
    expect(res.statusCode).toBe(403);
  });

  it.each(['ADMIN', 'ORGANIZER', 'SCANNER'])('admits %s', async (role) => {
    const email = freshEmail(`staff-${role}`);
    await signup(email);
    const userId = await trackByEmail(email);
    const { grantRole } = await import('../test-helpers/db.js');
    await grantRole(db, userId!, role);

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/admin/auth/signin',
      headers: { 'x-auth-transport': 'bearer' },
      payload: { email, password: PASSWORD },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().token).toBeTruthy();
    // Bearer and cookie are mutually exclusive.
    expect(res.headers['set-cookie']).toBeUndefined();
  });
});
