/**
 * Auth Service — Signup / Verify Email / Signin / Signout / Google OAuth
 *
 * Orchestration layer: calls security utilities + auth repository + email service.
 * No framework (Auth.js) — pure custom session management.
 *
 * Security invariants enforced here:
 *   - Email always normalized to lowercase before any DB lookup or insert.
 *   - passwordHash NEVER appears in any response object.
 *   - User existence is never revealed on login failure (returns INVALID_CREDENTIALS always).
 *   - BANNED / INACTIVE users receive FORBIDDEN (403), not INVALID_CREDENTIALS.
 *   - Email verification is required before password-login is allowed.
 *   - Google OAuth already verifies the email address, so Google sign-ins skip
 *     the app-owned OTP flow entirely and get a session immediately.
 *   - Raw session token never touches the DB — only its SHA-256 hash.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { v7 as uuidv7 } from 'uuid';
import crypto from 'node:crypto';
import { getAppDb, getWriterDb } from '../db/index.js';
import { GOOGLE_CALLBACK_PATH } from '../config/routes.js';
import { createDataError } from '../errors/DataError.js';
import { hashPassword, verifyPassword } from '../security/password.js';
import {
  generateOtp,
  generatePasswordResetToken,
  generateSessionToken,
  hashOtp,
  hashPasswordResetToken,
  hashSessionToken,
  verifyOtp,
} from '../security/jwt.js';
import {
  consumeVerificationToken,
  createSession,
  createUser,
  deleteSessionsForUser,
  deleteSession,
  findOrCreateOAuthUser,
  findUserByEmail,
  findUserById,
  findUserWithHashByEmail,
  findVerificationToken,
  findVerificationTokenByToken,
  markEmailVerified,
  updatePassword,
  verifyEmailAtomically,
  hasLinkedOAuthAccount,
  resetUserCredentials,
  upsertVerificationToken,
  consumeVerificationTokenByToken,
} from '../repositories/auth.repository.js';
import { getUserRoleAssignments } from '../repositories/user-roles.repository.js';
import { consumeHandoffCode, createHandoffCode } from '../repositories/console-handoffs.repository.js';
import { emailService } from './email.service.js';
import {
  assertAuthenticated,
  clearSessionCookie,
  setSessionCookie,
  BEARER_SESSION_MAX_AGE_MS,
  type AuthTransport,
} from '../plugins/jwt-auth.js';
import { loadConfig, type AppConfig } from '../config/env.js';
import { withTransaction } from '../db/transaction.js';

const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const CSRF_COOKIE_NAME = 'csrf_token';
const OAUTH_STATE_COOKIE_NAME = 'oauth_state';
const OAUTH_RETURN_TO_COOKIE_NAME = 'oauth_return_to';
const OAUTH_CLIENT_COOKIE_NAME = 'oauth_client';
const PASSWORD_RESET_PURPOSE = 'PASSWORD_RESET';
const PASSWORD_RESET_GENERIC_MESSAGE =
  'If an account exists for that email, we sent a password reset link.';

/**
 * Build the Google OAuth redirect URI.
 *
 * Used by BOTH the authorization-request builder and the callback handler. Google
 * requires the `redirect_uri` sent at each step to match byte-for-byte, and to
 * match what is registered in the Google Cloud Console — so these must never be
 * written as two separate literals. They previously were, which is a silent
 * production breakage waiting to happen: a drift between them fails at Google,
 * not in CI.
 */
function buildGoogleCallbackUrl(config: AppConfig): string {
  const callbackBase = config.OAUTH_CALLBACK_BASE_URL ?? config.FRONTEND_BASE_URL;
  return `${callbackBase.replace(/\/$/, '')}${GOOGLE_CALLBACK_PATH}`;
}

// ─── Helper: Issue CSRF token cookie ─────────────────────────────────────────

function issueCsrfToken(reply: FastifyReply): string {
  const csrfToken = crypto.randomBytes(24).toString('hex');
  reply.setCookie(CSRF_COOKIE_NAME, csrfToken, {
    httpOnly: false,    // Must be readable by frontend JS
    sameSite: 'strict',
    path: '/',
    // No maxAge — expires with browser session, refreshed on each login
  });
  return csrfToken;
}

// ─── Helper: Create session + set cookies ────────────────────────────────────

/**
 * Which credential the client is asking for, from the `X-Auth-Transport` header.
 *
 * Browsers get httpOnly cookies (default). The admin dashboard and mobile app
 * live on other origins where our cookie is third-party, so they opt into a
 * bearer token instead.
 */
export function resolveRequestedTransport(request: FastifyRequest): AuthTransport {
  return String(request.headers['x-auth-transport'] ?? '').toLowerCase() === 'bearer'
    ? 'bearer'
    : 'cookie';
}

/**
 * Create a session and hand back exactly ONE credential.
 *
 * Cookie and bearer are mutually exclusive by design. Issuing both would put the
 * same secret in a JS-readable response body *and* an httpOnly cookie, which
 * makes the httpOnly protection worthless — XSS could just read the body copy.
 *
 * Returns the raw token only for bearer callers; cookie callers get `null` and
 * the token never leaves the Set-Cookie header.
 */
async function createSessionAndIssueCredentials(
  userId: string,
  reply: FastifyReply,
  config: AppConfig,
  transport: AuthTransport,
): Promise<{ token: string; expiresAt: string } | null> {
  const db = getAppDb();
  const rawToken = generateSessionToken();
  const hashedToken = hashSessionToken(rawToken);
  const maxAgeMs = transport === 'bearer' ? BEARER_SESSION_MAX_AGE_MS : SESSION_MAX_AGE_MS;
  const expires = new Date(Date.now() + maxAgeMs);

  await createSession(db, {
    id: uuidv7(),
    userId,
    hashedToken,
    expires,
  });

  if (transport === 'bearer') {
    // No session cookie and no CSRF cookie: the client sends the token in an
    // Authorization header, which browsers never attach automatically, so there
    // is nothing for double-submit CSRF to protect.
    return { token: rawToken, expiresAt: expires.toISOString() };
  }

  setSessionCookie(reply, rawToken, { isProd: config.NODE_ENV !== 'development' });
  issueCsrfToken(reply);
  return null;
}

// ─── Email Verification ------------------------------------------------------

/**
 * Create and deliver the one-time code used by both password and Google
 * account flows. The token is stored before delivery so a transient SMTP
 * failure can be recovered by requesting another code without recreating the
 * account.
 */
async function sendVerificationCode(
  email: string,
  config: AppConfig,
): Promise<{ delivered: boolean }> {
  const otp = generateOtp();
  const hashedOtp = await hashOtp(otp);
  const otpExpires = new Date(Date.now() + config.OTP_EXPIRY_MINUTES * 60 * 1000);

  // Stored BEFORE any delivery attempt, so a failed send still leaves a token
  // that "resend" can replace and the user can eventually enter.
  await upsertVerificationToken(getWriterDb(), {
    identifier: email,
    hashedOtp,
    expires: otpExpires,
    purpose: 'EMAIL_VERIFICATION',
  });

  // ── SMTP DISABLED ─────────────────────────────────────────────────────────
  // Mail is not provisioned, and REQUIRE_EMAIL_VERIFICATION is off, so nothing
  // reaches this in normal operation. Re-enable together with that flag.
  //
  // try {
  //   await emailService.sendVerificationEmail({ to: email, verificationToken: otp });
  //   return { delivered: true };
  // } catch (error) {
  //   // Never leak SMTP details or the OTP to the browser.
  //   console.error(
  //     'Verification email delivery failed:',
  //     error instanceof Error ? error.message : String(error),
  //   );
  //   return { delivered: false };
  // }
  // ──────────────────────────────────────────────────────────────────────────

  // Returning `false` rather than throwing is the whole point: the caller
  // reports "created, code not sent" and keeps a recovery path open, instead
  // of 500-ing on a committed account.
  return { delivered: false };
}

// ─── 1. Sign Up (Password) ───────────────────────────────────────────────────

export interface SignupDto {
  email: string;
  password: string;
  username: string;
  fullName?: string;
}

export interface SignupResult {
  /**
   * ACTIVE            — account usable now, session issued alongside.
   * VERIFICATION_SENT — code delivered, caller must verify before signing in.
   * VERIFICATION_PENDING — account exists but the code did NOT go out.
   *
   * Machine-readable on purpose. This used to be prose only, so the website
   * could not tell "we emailed you" from "we could not email you" and printed
   * a delivery claim that was sometimes false.
   */
  status: 'ACTIVE' | 'VERIFICATION_SENT' | 'VERIFICATION_PENDING';
  message: string;
  user?: { id: string; email: string };
  token?: string;
  expiresAt?: string;
}

/**
 * Register a new user with email + password + unique character username.
 *
 * With REQUIRE_EMAIL_VERIFICATION off (the current default) the account is
 * created already verified and signed in — there is no pending state, and
 * therefore none of the lockout this flow used to produce when SMTP failed.
 *
 * With the flag on, the OTP path below runs instead and an unverified account
 * can always be recovered by signing up again (see the re-signup branch).
 */
export async function signupWithPassword(
  dto: SignupDto,
  config: AppConfig = loadConfig(),
  reply?: FastifyReply,
  transport: AuthTransport = 'cookie',
): Promise<SignupResult> {
  const db = getWriterDb();
  const email = dto.email.toLowerCase().trim();
  const requireVerification = config.REQUIRE_EMAIL_VERIFICATION;

  const existing = await findUserByEmail(db, email);

  if (existing) {
    // A Google-backed address is never claimable with a password — that would
    // graft a second credential onto an identity Google owns.
    if (await hasLinkedOAuthAccount(db, existing.id)) {
      throw createDataError('OAUTH_ACCOUNT');
    }
    // A verified account is a real one; refuse.
    if (existing.emailVerified) {
      throw createDataError('EMAIL_TAKEN');
    }
    // Unverified and password-backed: nobody ever proved they own this address,
    // so treat the signup as a retry rather than a collision. Without this, a
    // failed OTP delivery strands the address permanently — signin refuses an
    // unverified user and signup refuses a duplicate. Unreachable while the
    // flag is off (no unverified rows can be created), kept as the guard for
    // when verification is switched back on.
    await resetUserCredentials(db, {
      userId: existing.id,
      passwordHash: await hashPassword(dto.password),
      username: dto.username,
      fullName: dto.fullName,
    });
    const { delivered } = await sendVerificationCode(email, config);
    return {
      status: delivered ? 'VERIFICATION_SENT' : 'VERIFICATION_PENDING',
      message: delivered
        ? 'Account updated. A 6-digit verification code has been sent to your email.'
        : 'Account updated, but the verification code could not be sent. Please use "resend code".',
      user: { id: existing.id, email },
    };
  }

  const passwordHash = await hashPassword(dto.password);
  const userId = uuidv7();

  await createUser(db, {
    id: userId,
    email,
    passwordHash,
    username: dto.username,
    fullName: dto.fullName,
    emailVerified: requireVerification ? null : new Date(),
  });

  // Verification off: sign them straight in. No pending state exists, so there
  // is nothing to get stranded behind.
  if (!requireVerification) {
    const credentials = reply
      ? await createSessionAndIssueCredentials(userId, reply, config, transport)
      : null;
    return {
      status: 'ACTIVE',
      message: 'Account created.',
      user: { id: userId, email },
      ...(credentials ?? {}),
    };
  }

  // The account row is already committed, so a delivery failure must never fail
  // the request — that returned a 500 while leaving a real account behind, and
  // the retry then hit EMAIL_TAKEN. Report the outcome honestly instead; the
  // re-signup branch above and POST /auth/resend-verification are both exits.
  const { delivered } = await sendVerificationCode(email, config);
  return {
    status: delivered ? 'VERIFICATION_SENT' : 'VERIFICATION_PENDING',
    message: delivered
      ? 'Account created. A 6-digit verification code has been sent to your email.'
      : 'Account created, but the verification code could not be sent. Please use "resend code".',
    user: { id: userId, email },
  };
}

/**
 * Issue a replacement code without revealing whether an email is registered.
 * This is also the recovery path when an account was committed but SMTP was
 * temporarily unavailable during the original signup request.
 */
export async function resendVerificationCode(
  emailInput: string,
  config: AppConfig = loadConfig(),
): Promise<{ message: string }> {
  const email = emailInput.toLowerCase().trim();
  const user = await findUserByEmail(getAppDb(), email);
  if (user) {
    await sendVerificationCode(email, config);
  }

  return {
    message: 'If that account is awaiting verification, a new code has been sent.',
  };
}

// ─── Password Reset ----------------------------------------------------------

/**
 * Request a password reset without revealing whether an email is registered.
 * Only password-backed, active, already-verified accounts receive a link. OAuth
 * accounts continue to use Google sign-in and cannot be converted into a
 * password account through this public recovery endpoint.
 */
export async function requestPasswordReset(
  emailInput: string,
  config: AppConfig = loadConfig(),
): Promise<{ message: string }> {
  const email = emailInput.toLowerCase().trim();
  const db = getWriterDb();
  const user = await findUserWithHashByEmail(db, email);

  if (
    user?.passwordHash &&
    user.status !== 'BANNED' &&
    user.status !== 'INACTIVE' &&
    user.emailVerified
  ) {
    const rawToken = generatePasswordResetToken();
    const hashedToken = hashPasswordResetToken(rawToken);
    const expires = new Date(Date.now() + config.PASSWORD_RESET_EXPIRY_MINUTES * 60 * 1000);

    await upsertVerificationToken(db, {
      identifier: user.email,
      hashedOtp: hashedToken,
      expires,
      purpose: PASSWORD_RESET_PURPOSE,
    });

    const resetUrl = `${config.FRONTEND_BASE_URL.replace(/\/$/, '')}/reset-password?token=${encodeURIComponent(rawToken)}`;
    try {
      await emailService.sendPasswordResetEmail({
        to: user.email,
        resetUrl,
        expiryMinutes: config.PASSWORD_RESET_EXPIRY_MINUTES,
      });
    } catch (error) {
      // Keep the response identical to the unknown-email case. The token is
      // intentionally left replaceable through another request.
      console.error(
        'Password reset email delivery failed:',
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  return { message: PASSWORD_RESET_GENERIC_MESSAGE };
}

/**
 * Consume a valid reset link and rotate the user's password and all sessions
 * in one transaction. The token row is locked before it is consumed, so two
 * concurrent requests cannot successfully reuse the same link.
 */
export async function resetPassword(
  rawToken: string,
  newPassword: string,
): Promise<{ message: string }> {
  const invalidError = createDataError(
    'INVALID_CREDENTIALS',
    'This password reset link is invalid or expired.',
  );
  const hashedToken = hashPasswordResetToken(rawToken);

  const succeeded = await withTransaction(getWriterDb(), async (tx) => {
    const tokenRow = await findVerificationTokenByToken(
      tx,
      hashedToken,
      PASSWORD_RESET_PURPOSE,
    );

    if (!tokenRow) return false;

    const expires =
      typeof tokenRow.expires === 'string' ? new Date(tokenRow.expires) : tokenRow.expires;
    const user = await findUserWithHashByEmail(tx, tokenRow.identifier);

    if (
      Date.now() > expires.getTime() ||
      !user?.passwordHash ||
      user.status === 'BANNED' ||
      user.status === 'INACTIVE'
    ) {
      await consumeVerificationTokenByToken(tx, hashedToken, PASSWORD_RESET_PURPOSE);
      return false;
    }

    await consumeVerificationTokenByToken(tx, hashedToken, PASSWORD_RESET_PURPOSE);
    await updatePassword(tx, user.id, await hashPassword(newPassword));
    await deleteSessionsForUser(tx, user.id);
    return true;
  });

  if (!succeeded) throw invalidError;
  return { message: 'Password reset successfully. You can now sign in.' };
}

// ─── 2. Verify Email (OTP) ───────────────────────────────────────────────────

export interface VerifyEmailDto {
  email: string;
  otp: string;
}

/**
 * Verify email with the 6-digit OTP sent during signup.
 *
 * Flow:
 *  1. Find pending verification token for this email.
 *  2. Check not expired.
 *  3. bcrypt.compare(otp, storedHash).
 *  4. Atomically: markEmailVerified + consumeVerificationToken.
 *  5. Create session → set __session cookie + csrf_token cookie.
 *  6. Return { user } — user is now logged in.
 */
export async function verifyEmail(
  dto: VerifyEmailDto,
  reply: FastifyReply,
  config: AppConfig,
  transport: AuthTransport = 'cookie',
): Promise<{
  message: string;
  user: { id: string; email: string };
  token?: string;
  expiresAt?: string;
}> {
  const db = getWriterDb();
  const email = dto.email.toLowerCase().trim();

  // Verification is off: there is no pending state for this route to resolve,
  // and accounts are already created verified. Say so plainly rather than
  // returning "invalid code", which would send the caller hunting for an email
  // that was never sent. The route stays registered either way.
  if (!config.REQUIRE_EMAIL_VERIFICATION) {
    throw createDataError(
      'EMAIL_NOT_VERIFIED',
      'Email verification is currently disabled. You can sign in directly.',
    );
  }

  const tokenRow = await findVerificationToken(db, email, 'EMAIL_VERIFICATION');

  // Generic error to avoid revealing whether the email exists or the OTP is wrong
  const invalidError = createDataError(
    'INVALID_CREDENTIALS',
    'Invalid or expired verification code.',
  );

  if (!tokenRow) throw invalidError;

  // Check expiry
  const expires =
    typeof tokenRow.expires === 'string' ? new Date(tokenRow.expires) : tokenRow.expires;
  if (Date.now() > expires.getTime()) {
    await consumeVerificationToken(db, email, 'EMAIL_VERIFICATION');
    throw invalidError;
  }

  // Verify OTP (timing-safe bcrypt compare)
  const valid = await verifyOtp(dto.otp, tokenRow.token);
  if (!valid) throw invalidError;

  const user = await findUserWithHashByEmail(db, email);
  if (!user) throw invalidError; // Shouldn't happen, but guard anyway

  // Same suspension gate as signin. Without it, a banned user holding a valid
  // code could verify and be handed a fresh session through this route.
  if (user.status === 'BANNED' || user.status === 'INACTIVE') {
    throw createDataError('FORBIDDEN', 'Your account has been suspended.');
  }

  // One transaction, not Promise.all — see verifyEmailAtomically.
  await verifyEmailAtomically(db, { userId: user.id, email });

  // Create session — user is logged in immediately after verification
  const credentials = await createSessionAndIssueCredentials(user.id, reply, config, transport);

  return {
    message: 'Email verified successfully. You are now signed in.',
    user: { id: user.id, email: user.email },
    ...(credentials ?? {}),
  };
}

// ─── 3. Sign In (Password) ───────────────────────────────────────────────────

export interface SigninDto {
  email: string;
  password: string;
}

/**
 * Authenticate an existing user with email + password.
 *
 * Flow:
 *  1. Look up user by email (with passwordHash for verification).
 *  2. INVALID_CREDENTIALS if user not found (never reveal existence).
 *  3. FORBIDDEN if status is BANNED or INACTIVE.
 *  4. VALIDATION_FAILED if email is not yet verified.
 *  5. bcrypt.compare password — INVALID_CREDENTIALS on mismatch.
 *  6. Create session → set __session cookie + csrf_token cookie.
 */
/**
 * Verify an email + password WITHOUT creating a session.
 *
 * Split out so callers can insert extra checks between "these credentials are
 * valid" and "issue a credential". The admin door needs exactly that: it must
 * reject a non-admin *before* a session row exists, otherwise a rejected login
 * still leaves a usable token behind for the participant API.
 *
 * Throws INVALID_CREDENTIALS for both unknown users and wrong passwords, so the
 * endpoint cannot be used to enumerate registered emails.
 */
export async function verifyPasswordCredentials(
  dto: SigninDto,
  config: AppConfig = loadConfig(),
): Promise<{ id: string; email: string }> {
  const db = getAppDb();
  const email = dto.email.toLowerCase().trim();

  const user = await findUserWithHashByEmail(db, email);

  // Existence check. An OAuth-only account (passwordHash === null) falls in
  // here deliberately: telling the caller "this one signs in with Google"
  // would confirm the address exists to anyone who asks. The UI carries a
  // static "signed up with Google?" hint instead, which reveals nothing.
  if (!user || !user.passwordHash) {
    throw createDataError('INVALID_CREDENTIALS');
  }

  // Suspended account
  if (user.status === 'BANNED' || user.status === 'INACTIVE') {
    throw createDataError('FORBIDDEN', 'Your account has been suspended.');
  }

  // Password FIRST, verification state second.
  //
  // The reverse order was a user-enumeration oracle: a wrong password against
  // an unverified account answered EMAIL_NOT_VERIFIED while a wrong password
  // against an unknown address answered INVALID_CREDENTIALS, so anyone could
  // sift real addresses out of a wordlist without ever guessing a password.
  // Nothing about the account may leak until the password is proven.
  const { valid, needsRehash } = await verifyPassword(dto.password, user.passwordHash);
  if (!valid) {
    throw createDataError('INVALID_CREDENTIALS');
  }

  // Upgrade a surviving bcrypt hash now that we hold the plaintext. This is the
  // only moment it is available. Deliberately not awaited into the critical
  // path — a slow write must not delay the login response, and a failed one
  // just means the upgrade happens on their next sign-in instead.
  if (needsRehash) {
    hashPassword(dto.password)
      .then((upgraded) => updatePassword(getWriterDb(), user.id, upgraded))
      .catch((err) => console.error('Password rehash failed (non-fatal):', err));
  }

  // Verification gate — only when the flag is on. See REQUIRE_EMAIL_VERIFICATION
  // in src/config/env.ts for why it is off.
  if (config.REQUIRE_EMAIL_VERIFICATION && !user.emailVerified) {
    // Reissue on the way out so the caller has a fresh code to enter. The user
    // has proven the password, so this reveals nothing they did not already know.
    sendVerificationCode(email, config).catch((err) =>
      console.error('Could not reissue verification code:', err),
    );
    throw createDataError('EMAIL_NOT_VERIFIED');
  }

  return { id: user.id, email: user.email };
}

export async function signinWithPassword(
  dto: SigninDto,
  reply: FastifyReply,
  config: AppConfig,
  transport: AuthTransport = 'cookie',
): Promise<{ user: { id: string; email: string }; token?: string; expiresAt?: string }> {
  const user = await verifyPasswordCredentials(dto);
  const credentials = await createSessionAndIssueCredentials(user.id, reply, config, transport);

  return { user, ...(credentials ?? {}) };
}

/**
 * Issue a session for an already-verified user.
 *
 * Exported for the admin signin door, which verifies credentials, checks the
 * ADMIN role, and only then asks for a credential.
 */
export async function issueSessionFor(
  userId: string,
  reply: FastifyReply,
  config: AppConfig,
  transport: AuthTransport,
): Promise<{ token: string; expiresAt: string } | null> {
  return createSessionAndIssueCredentials(userId, reply, config, transport);
}

// ─── 4. Sign Out ─────────────────────────────────────────────────────────────

/**
 * Revoke the current session and clear auth cookies.
 * No-op if the session is already gone (idempotent).
 */
export async function signout(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  assertAuthenticated(request);

  const db = getAppDb();
  if (request._rawSessionToken) {
    const hashedToken = hashSessionToken(request._rawSessionToken);
    await deleteSession(db, hashedToken);
  }

  clearSessionCookie(reply);
}

/**
 * Console logout is an explicit "sign out everywhere" action. The console
 * bearer session and the website's cookie session belong to the same user, so
 * revoking only the bearer would leave the website session alive and allow a
 * fresh console handoff immediately afterward.
 */
export async function signoutEverywhere(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  assertAuthenticated(request);
  await deleteSessionsForUser(getWriterDb(), request.user.id);
  clearSessionCookie(reply);
}

// ─── 5. Get Current Session ───────────────────────────────────────────────────

/**
 * Return the currently authenticated user from the session hook decoration.
 * Throws NOT_AUTHENTICATED if no valid session exists.
 */
export function getSession(request: FastifyRequest): {
  id: string;
  email: string;
  status: string;
  emailVerified: Date | string | null;
  mustChangePassword: boolean;
} {
  assertAuthenticated(request);
  return request.user;
}

export async function changePassword(
  request: FastifyRequest,
  reply: FastifyReply,
  config: AppConfig,
  dto: { currentPassword: string; newPassword: string },
): Promise<{ message: string; user: { id: string; email: string }; token?: string; expiresAt?: string }> {
  assertAuthenticated(request);
  const db = getAppDb();
  const user = await findUserWithHashByEmail(db, request.user.email);
  // An OAuth account has no password to change. Safe to say so plainly: this
  // route requires an authenticated session, so the caller already knows the
  // account exists — there is nothing left to enumerate.
  if (!user?.passwordHash) {
    throw createDataError('OAUTH_ACCOUNT');
  }
  const { valid } = await verifyPassword(dto.currentPassword, user.passwordHash);
  if (!valid) {
    throw createDataError('INVALID_CREDENTIALS', 'Current password is incorrect.');
  }

  await updatePassword(db, request.user.id, await hashPassword(dto.newPassword));
  await deleteSessionsForUser(db, request.user.id);
  const credentials = await createSessionAndIssueCredentials(
    request.user.id,
    reply,
    config,
    request.authTransport ?? 'cookie',
  );

  return {
    message: 'Password changed successfully.',
    user: { id: request.user.id, email: request.user.email },
    ...(credentials ?? {}),
  };
}

export async function createConsoleHandoff(
  request: FastifyRequest,
  config: AppConfig,
  returnTo = '/',
): Promise<{ url: string; expiresAt: string }> {
  assertAuthenticated(request);
  if (request.user.mustChangePassword) {
    throw createDataError('MUST_CHANGE_PASSWORD', 'Change the temporary password before opening the console.');
  }
  const assignments = await getUserRoleAssignments(getAppDb(), request.user.id);
  if (!assignments.some((assignment) => ['ADMIN', 'ORGANIZER', 'SCANNER'].includes(assignment.role))) {
    throw createDataError('FORBIDDEN', 'This account does not have console access.');
  }

  const code = await createHandoffCode(getAppDb(), { userId: request.user.id, returnTo });
  const expiresAt = new Date(Date.now() + 90_000).toISOString();
  const url = `${config.REGISTRATION_CONSOLE_URL.replace(/\/$/, '')}/auth/callback?code=${encodeURIComponent(code)}&returnTo=${encodeURIComponent(returnTo)}`;
  return { url, expiresAt };
}

export async function exchangeConsoleHandoff(
  code: string,
  reply: FastifyReply,
  config: AppConfig,
): Promise<{
  token: string;
  expiresAt: string;
  returnTo: string;
  user: { id: string; email: string; status: string; mustChangePassword: boolean };
  roles: Array<{ role: string; eventScopeId: string | null }>;
}> {
  const db = getAppDb();
  const handoff = await consumeHandoffCode(db, code);
  if (!handoff) throw createDataError('INVALID_CREDENTIALS', 'This console sign-in link is invalid or expired.');

  const user = await findUserById(db, handoff.userId);
  if (!user || user.mustChangePassword) {
    throw createDataError('MUST_CHANGE_PASSWORD', 'The staff account must change its temporary password first.');
  }
  const roles = await getUserRoleAssignments(db, user.id);
  if (!roles.some((assignment) => ['ADMIN', 'ORGANIZER', 'SCANNER'].includes(assignment.role))) {
    throw createDataError('FORBIDDEN', 'This account no longer has console access.');
  }
  const credentials = await issueSessionFor(user.id, reply, config, 'bearer');
  if (!credentials) throw createDataError('INTERNAL_ERROR', 'Could not create console session.');

  return {
    token: credentials.token,
    expiresAt: credentials.expiresAt,
    returnTo: handoff.returnTo,
    user: {
      id: user.id,
      email: user.email,
      status: user.status,
      mustChangePassword: user.mustChangePassword,
    },
    roles: roles.map((assignment) => ({ role: assignment.role, eventScopeId: assignment.eventScopeId })),
  };
}

/**
 * The reverse of `createConsoleHandoff`: a staff member already signed into the
 * registration console can hand their session back to the website. Reuses the
 * same one-time-code table with `target: 'website'` rather than a second table.
 *
 * This must be a real browser navigation, not a background fetch — the
 * website's session cookie is issued for the website's own origin, and a
 * cross-origin request from the console cannot set it (this is also why the
 * console session is a bearer token in the first place, see `signoutEverywhere`
 * above). The console UI triggers this explicitly (e.g. an "Open participant
 * site" action), it is not automatic on every console sign-in.
 */
export async function createWebsiteHandoff(
  request: FastifyRequest,
  config: AppConfig,
  returnTo = '/',
): Promise<{ url: string; expiresAt: string }> {
  assertAuthenticated(request);
  const code = await createHandoffCode(getAppDb(), { userId: request.user.id, returnTo, target: 'website' });
  const expiresAt = new Date(Date.now() + 90_000).toISOString();
  const url = `${config.FRONTEND_BASE_URL.replace(/\/$/, '')}/auth/console-return?code=${encodeURIComponent(code)}&returnTo=${encodeURIComponent(returnTo)}`;
  return { url, expiresAt };
}

export async function exchangeWebsiteHandoff(
  code: string,
  reply: FastifyReply,
  config: AppConfig,
): Promise<{
  expiresAt: string;
  returnTo: string;
  user: { id: string; email: string; status: string; mustChangePassword: boolean };
}> {
  const db = getAppDb();
  const handoff = await consumeHandoffCode(db, code, 'website');
  if (!handoff) throw createDataError('INVALID_CREDENTIALS', 'This sign-in link is invalid or expired.');

  const user = await findUserById(db, handoff.userId);
  if (!user) throw createDataError('NOT_AUTHENTICATED', 'Account no longer exists.');

  const credentials = await issueSessionFor(user.id, reply, config, 'cookie');
  if (!credentials) throw createDataError('INTERNAL_ERROR', 'Could not create website session.');

  return {
    expiresAt: credentials.expiresAt,
    returnTo: handoff.returnTo,
    user: {
      id: user.id,
      email: user.email,
      status: user.status,
      mustChangePassword: user.mustChangePassword,
    },
  };
}

// ─── 6. Google OAuth — Initiate ──────────────────────────────────────────────

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_SCOPES = 'openid email profile';

/**
 * Build the Google OAuth2 authorization redirect URL.
 * Frontend should redirect the user to the returned URL.
 */
export function initiateGoogleOAuth(
  config: AppConfig,
  reply: FastifyReply,
  returnTo = '/travelling',
  /**
   * 'console' routes the callback to the registration console instead of the
   * website — see the `client` branch in handleGoogleCallback. Carried in its
   * own signed cookie alongside state/returnTo so it survives the same
   * round-trip and cannot be forged (the callback only trusts what it signed).
   */
  client: 'website' | 'console' = 'website',
): { url: string } {
  if (!config.OAUTH_GOOGLE_CLIENT_ID) {
    throw createDataError('INTERNAL_ERROR', 'Google OAuth is not configured on this server.');
  }

  const callbackUrl = buildGoogleCallbackUrl(config);
  const state = crypto.randomBytes(16).toString('hex'); // CSRF state param

  // Persist the state so the callback can prove this flow started here. It was
  // previously generated, sent to Google, and then never checked — which left
  // login-CSRF wide open: an attacker could feed a victim their own auth code and
  // silently bind the victim's browser to the attacker's Google account.
  //
  // A signed httpOnly cookie is enough; the value is single-use and short-lived,
  // so it needs no DB row.
  reply.setCookie(OAUTH_STATE_COOKIE_NAME, state, {
    httpOnly: true,
    secure: config.NODE_ENV !== 'development',
    // 'lax' (not 'strict') is required: the cookie must survive Google's
    // top-level redirect back to the callback.
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60, // 10 minutes — an OAuth round-trip, not a session
    signed: true,
  });
  reply.setCookie(OAUTH_RETURN_TO_COOKIE_NAME, returnTo, {
    httpOnly: true,
    secure: config.NODE_ENV !== 'development',
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60,
    signed: true,
  });
  reply.setCookie(OAUTH_CLIENT_COOKIE_NAME, client, {
    httpOnly: true,
    secure: config.NODE_ENV !== 'development',
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60,
    signed: true,
  });

  const params = new URLSearchParams({
    client_id: config.OAUTH_GOOGLE_CLIENT_ID,
    redirect_uri: callbackUrl,
    response_type: 'code',
    scope: GOOGLE_SCOPES,
    access_type: 'offline',
    prompt: 'consent',
    state,
  });

  return { url: `${GOOGLE_AUTH_URL}?${params.toString()}` };
}

// ─── 7. Google OAuth — Callback ───────────────────────────────────────────────

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

interface GoogleTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  id_token?: string;
  scope: string;
  token_type: string;
}

interface GoogleUserInfo {
  sub: string;   // Google's unique user ID
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
}

/**
 * Handle the Google OAuth callback after the user grants consent.
 *
 * Flow:
 *  1. Exchange authorization code for Google tokens.
 *  2. Fetch Google userinfo (email, name, picture).
 *  3. find-or-create user + link OAuth account (atomic DB transaction).
 *  4. Google has already verified the email, so a session is issued directly —
 *     no app-owned OTP round-trip, no SMTP dependency on this path.
 */
export async function handleGoogleCallback(
  code: string,
  request: FastifyRequest,
  reply: FastifyReply,
  config: AppConfig,
  state?: string,
): Promise<{
  user: { id: string; email: string };
  requiresVerification: false;
  returnTo: string;
  token?: string;
  expiresAt?: string;
  /**
   * Set only for the console flow (`client=console` at /signin/google). The
   * route redirects here instead of into the website — a bearer token cannot
   * ride safely in a redirect URL, so this points at a one-time handoff code
   * exchanged server-side by the console's own callback route, reusing the
   * same console_handoffs machinery as the website's "open console" button.
   */
  redirectUrl?: string;
}> {
  if (!config.OAUTH_GOOGLE_CLIENT_ID || !config.OAUTH_GOOGLE_CLIENT_SECRET) {
    throw createDataError('INTERNAL_ERROR', 'Google OAuth is not configured on this server.');
  }

  // Verify the state round-tripped from initiateGoogleOAuth before spending the
  // authorization code. Consume the cookie either way so a state can't be replayed.
  const stateCookie = request.cookies[OAUTH_STATE_COOKIE_NAME];
  reply.clearCookie(OAUTH_STATE_COOKIE_NAME, { path: '/' });
  const returnToCookie = request.cookies[OAUTH_RETURN_TO_COOKIE_NAME];
  reply.clearCookie(OAUTH_RETURN_TO_COOKIE_NAME, { path: '/' });
  const clientCookie = request.cookies[OAUTH_CLIENT_COOKIE_NAME];
  reply.clearCookie(OAUTH_CLIENT_COOKIE_NAME, { path: '/' });
  const unsignedClient = clientCookie ? request.unsignCookie(clientCookie) : null;
  const client = unsignedClient?.valid && unsignedClient.value === 'console' ? 'console' : 'website';

  const expectedState = stateCookie ? request.unsignCookie(stateCookie) : null;
  const requestedReturnTo = returnToCookie ? request.unsignCookie(returnToCookie) : null;
  const returnTo = requestedReturnTo?.valid && requestedReturnTo.value
    ? requestedReturnTo.value
    : '/travelling';
  if (
    !state ||
    !expectedState?.valid ||
    !expectedState.value ||
    expectedState.value.length !== state.length ||
    !crypto.timingSafeEqual(Buffer.from(expectedState.value), Buffer.from(state))
  ) {
    throw createDataError('VALIDATION_FAILED', 'Invalid or expired OAuth state.');
  }

  const callbackUrl = buildGoogleCallbackUrl(config);

  // Step 1: exchange code for tokens
  const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: config.OAUTH_GOOGLE_CLIENT_ID,
      client_secret: config.OAUTH_GOOGLE_CLIENT_SECRET,
      redirect_uri: callbackUrl,
      grant_type: 'authorization_code',
    }),
  });

  if (!tokenRes.ok) {
    throw createDataError('INVALID_CREDENTIALS', 'Failed to exchange Google authorization code.');
  }

  const tokens = (await tokenRes.json()) as GoogleTokenResponse;

  // Step 2: fetch userinfo
  const userInfoRes = await fetch(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });

  if (!userInfoRes.ok) {
    throw createDataError('INTERNAL_ERROR', 'Failed to fetch Google user profile.');
  }

  const googleUser = (await userInfoRes.json()) as GoogleUserInfo;

  if (!googleUser.email || !googleUser.email_verified) {
    throw createDataError(
      'VALIDATION_FAILED',
      'Google account email is not verified. Please verify your Google account first.',
    );
  }

  // Step 3: find-or-create user + link OAuth account
  const db = getAppDb();
  const expiresAt = Math.floor(Date.now() / 1000) + tokens.expires_in;

  const userId = await findOrCreateOAuthUser(db, {
    userId: uuidv7(),
    accountId: uuidv7(),
    email: googleUser.email,
    provider: 'google',
    providerAccountId: googleUser.sub,
    googleProfile: {
      name: googleUser.name,
      picture: googleUser.picture,
      expiresAt,
      idToken: tokens.id_token,
      scope: tokens.scope,
    },
  });

  // Step 4: Google already confirmed this identity and email ownership — no
  // app-owned OTP is needed, so a session is issued immediately. Still gate on
  // account status, same as password signin, so a banned/inactive account can't
  // bypass that check by going through Google instead.
  const user = await findUserById(db, userId);
  if (!user) throw createDataError('INTERNAL_ERROR', 'Could not load the signed-in account.');
  if (user.status === 'BANNED' || user.status === 'INACTIVE') {
    throw createDataError('FORBIDDEN', 'Your account has been suspended.');
  }

  if (client === 'console') {
    // Same staff gate createConsoleHandoff applies to an existing session —
    // there is no session yet here, so it is inlined rather than reused.
    const assignments = await getUserRoleAssignments(getAppDb(), userId);
    if (!assignments.some((a) => ['ADMIN', 'ORGANIZER', 'SCANNER'].includes(a.role))) {
      throw createDataError('FORBIDDEN', 'This account does not have console access.');
    }
    if (user.mustChangePassword) {
      throw createDataError(
        'MUST_CHANGE_PASSWORD',
        'Change the temporary password before opening the console.',
      );
    }
    const handoffCode = await createHandoffCode(getWriterDb(), { userId, returnTo });
    const redirectUrl =
      `${config.REGISTRATION_CONSOLE_URL.replace(/\/$/, '')}/auth/callback` +
      `?code=${encodeURIComponent(handoffCode)}&returnTo=${encodeURIComponent(returnTo)}`;
    return {
      user: { id: userId, email: googleUser.email },
      requiresVerification: false,
      returnTo,
      redirectUrl,
    };
  }

  const credentials = await createSessionAndIssueCredentials(userId, reply, config, 'cookie');

  return {
    user: { id: userId, email: googleUser.email },
    requiresVerification: false,
    returnTo,
    ...(credentials ?? {}),
  };
}
