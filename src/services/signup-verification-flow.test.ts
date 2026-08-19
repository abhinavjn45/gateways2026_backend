/**
 * Regression coverage for the deployed-backend bug this session fixed:
 * signupWithPassword() used to `await` the full mail-delivery chain
 * (relay -> primary SMTP -> fallback SMTP) before responding. On Render
 * that chain measurably outlasts the platform's own proxy timeout — the
 * client received zero bytes back, even though the account row had already
 * committed. From the user's perspective: "it creates the account but
 * never shows the OTP screen."
 *
 * The fix splits token issuance (fast, DB-only, still awaited) from mail
 * delivery (slow, unreliable, now fired without awaiting). These tests
 * prove the split actually holds: the HTTP response must return well
 * before a slow/never-resolving delivery attempt does, and the token must
 * already be usable the instant the response comes back.
 *
 * REQUIRE_EMAIL_VERIFICATION is set before buildApp() runs so this file's
 * loadConfig() cache picks it up — vitest isolates module state per test
 * file by default, so this does not leak into other suites.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { users, verificationTokens } from '../db/schema/auth.js';

process.env.REQUIRE_EMAIL_VERIFICATION = 'true';

const { buildApp } = await import('../app.js');
const { getAppDb } = await import('../db/index.js');
const { deleteTestUser } = await import('../test-helpers/db.js');
const { emailService } = await import('./email.service.js');

const db = getAppDb();
let app: FastifyInstance;
const cleanup: string[] = [];

function freshEmail(tag: string) {
  return `otpflow-${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
}

beforeAll(async () => {
  ({ app } = await buildApp());
  await app.ready();
});

afterAll(async () => {
  for (const id of cleanup) await deleteTestUser(db, id).catch(() => {});
  vi.restoreAllMocks();
  await app.close();
});

describe('signup response does not block on mail delivery', () => {
  it('returns well before a slow delivery attempt resolves', async () => {
    // Deliberately slower than any reasonable HTTP client/proxy timeout would
    // tolerate — if the response ever depended on this resolving, the test
    // itself would time out (default vitest test timeout is 5s+ here via
    // vitest.config.ts's 15s hookTimeout/testTimeout).
    let deliveryResolved = false;
    const deliverySpy = vi
      .spyOn(emailService, 'sendVerificationEmail')
      .mockImplementation(async () => {
        await new Promise((r) => setTimeout(r, 3000));
        deliveryResolved = true;
        return { success: true, provider: 'primary' };
      });

    const email = freshEmail('slow');
    const started = Date.now();
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email, password: 'hunter2hunter2', username: `U${Math.random().toString(36).slice(2, 10)}` },
    });
    const elapsedMs = Date.now() - started;

    const row = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
    if (row[0]) cleanup.push(row[0].id);

    expect(res.statusCode).toBe(201);
    expect(res.json().status).toBe('VERIFICATION_SENT');
    // The whole point: the response must not have waited for the 3s mock.
    expect(elapsedMs).toBeLessThan(1500);
    expect(deliveryResolved).toBe(false);

    deliverySpy.mockRestore();
  });

  it('has already stored a usable OTP token by the time the response returns', async () => {
    const deliverySpy = vi
      .spyOn(emailService, 'sendVerificationEmail')
      .mockImplementation(async () => {
        await new Promise((r) => setTimeout(r, 2000));
        return { success: true, provider: 'primary' };
      });

    const email = freshEmail('token-ready');
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email, password: 'hunter2hunter2', username: `U${Math.random().toString(36).slice(2, 10)}` },
    });

    const row = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
    if (row[0]) cleanup.push(row[0].id);

    expect(res.statusCode).toBe(201);

    // Queried immediately after the response, with the delivery mock still
    // pending — token issuance must not have waited on delivery either.
    const tokenRows = await db
      .select({ identifier: verificationTokens.identifier })
      .from(verificationTokens)
      .where(eq(verificationTokens.identifier, email));
    expect(tokenRows.length).toBeGreaterThan(0);

    deliverySpy.mockRestore();
  });

  it('completes the full OTP round trip once delivery eventually happens', async () => {
    let capturedOtp: string | null = null;
    const deliverySpy = vi
      .spyOn(emailService, 'sendVerificationEmail')
      .mockImplementation(async (opts: { verificationToken: string }) => {
        capturedOtp = opts.verificationToken;
        return { success: true, provider: 'primary' };
      });

    const email = freshEmail('roundtrip');
    const signupRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email, password: 'hunter2hunter2', username: `U${Math.random().toString(36).slice(2, 10)}` },
    });
    expect(signupRes.statusCode).toBe(201);

    const row = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
    if (row[0]) cleanup.push(row[0].id);

    // The mock resolves fast here, but it is still fired-and-forgotten by the
    // route — give the microtask queue a beat to run it before asserting.
    await new Promise((r) => setTimeout(r, 50));
    expect(capturedOtp).not.toBeNull();

    const verifyRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/verify-email',
      payload: { email, otp: capturedOtp },
    });
    expect(verifyRes.statusCode).toBe(200);
    expect(String(verifyRes.headers['set-cookie'])).toContain('__session=');

    deliverySpy.mockRestore();
  });
});
