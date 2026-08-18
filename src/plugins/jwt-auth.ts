/**
 * Session Auth Plugin — Global onRequest Hook
 *
 * Validates the `__session` httpOnly cookie on every request:
 *   1. Reads + unsigns the session cookie using @fastify/cookie's built-in signing.
 *   2. SHA-256 hashes the raw token to look up the session in DB.
 *   3. If valid & not expired: decorates `request.user` + slides the session expiry.
 *   4. If missing/invalid/expired: does nothing — routes that require auth
 *      must call assertAuthenticated() to enforce protection.
 *
 * This plugin also exports:
 *   - assertAuthenticated(request) — throws NOT_AUTHENTICATED if no user is set
 *   - SESSION_COOKIE_NAME — the canonical cookie name used everywhere
 *
 * IDOR invariant: request.user is ONLY set from a DB-verified session row.
 * Client-supplied userId values are never trusted.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { getAppDb } from '../db/index.js';
import { createDataError } from '../errors/DataError.js';
import { hashSessionToken } from '../security/jwt.js';
import {
  deleteExpiredSessions,
  findSessionByHashedToken,
  touchSession,
} from '../repositories/auth.repository.js';

// ─── Public Types ─────────────────────────────────────────────────────────────

export interface AuthenticatedUser {
  id: string;
  email: string;
  status: string;
  emailVerified: Date | string | null;
  mustChangePassword: boolean;
}

/**
 * How the caller presented their session token on this request.
 *
 *   'cookie' — the httpOnly `__session` cookie (website). Browser-attached, so
 *              CSRF protection applies.
 *   'bearer' — an `Authorization: Bearer` header (admin dashboard, mobile).
 *              Not browser-attached, so CSRF protection does not apply.
 */
export type AuthTransport = 'cookie' | 'bearer';

// Augment FastifyRequest so TypeScript knows about request.user everywhere
declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
    /** Raw (unsigned) session token — stored only during this request lifecycle */
    _rawSessionToken?: string;
    /**
     * Set ONLY alongside `user`, and only after the session row has been
     * verified. The CSRF hook keys its Bearer skip off this, so a forged or
     * malformed Authorization header must never leave it set.
     */
    authTransport?: AuthTransport;
    /**
     * ISO timestamp of the current session row's expiry. Set alongside
     * request.user so GET /auth/session can return the server's real value
     * instead of a client having to invent one from a fixed session lifetime
     * that may not match (e.g. after a slide, or a shorter bearer window).
     */
    sessionExpiresAt?: string;
  }
}

// ─── Constants ────────────────────────────────────────────────────────────────

export const SESSION_COOKIE_NAME = '__session';
export const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
/**
 * Bearer sessions get a shorter, non-sliding window. They live in JS-reachable
 * storage on the client (the dashboard can't use our httpOnly cookie — different
 * domain), so a stolen one is worth strictly more than a stolen cookie. 12h
 * covers a full fest shift without renewing itself indefinitely.
 */
export const BEARER_SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000; // 12 hours
// Slide expiry only if the session is within the last day of its window
// to avoid a DB write on every single request
const SLIDE_THRESHOLD_MS = 24 * 60 * 60 * 1000; // 1 day

/**
 * Pull the session token off the request, preferring an Authorization header
 * over the cookie.
 *
 * Bearer wins outright: if the header is present but unusable we return null
 * rather than falling back to the cookie. That is what makes the CSRF skip safe —
 * an attacker who can forge a header but not read the victim's token must not be
 * able to ride the victim's cookie while suppressing the CSRF check.
 *
 * The cookie value is `<raw>.<hmac>` (set with `signed: true`); the Bearer value
 * is the raw token. Both hash to the same DB lookup, so there is exactly one
 * session store regardless of transport.
 */
export function extractSessionToken(
  request: FastifyRequest,
): { token: string; transport: AuthTransport } | null {
  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.slice(0, 7).toLowerCase() === 'bearer ') {
    const token = authHeader.slice(7).trim();
    return token ? { token, transport: 'bearer' } : null;
  }

  const rawCookieValue = request.cookies[SESSION_COOKIE_NAME];
  if (!rawCookieValue) return null;

  const unsigned = request.unsignCookie(rawCookieValue);
  if (!unsigned.valid || !unsigned.value) return null;

  return { token: unsigned.value, transport: 'cookie' };
}

// ─── Plugin Registration ──────────────────────────────────────────────────────

export async function registerSessionHook(app: FastifyInstance): Promise<void> {
  // Purge stale sessions once on startup (fire-and-forget)
  deleteExpiredSessions(getAppDb()).catch((err) => {
    app.log.warn({ err }, 'Failed to purge expired sessions on startup — non-fatal');
  });

  app.addHook('onRequest', async (request) => {
    const extracted = extractSessionToken(request);
    if (!extracted) return; // No usable credential — unauthenticated, proceed

    const rawToken = extracted.token;
    const hashedToken = hashSessionToken(rawToken);

    const db = getAppDb();
    const result = await findSessionByHashedToken(db, hashedToken);
    if (!result) return; // Session not found or expired

    const { session, user } = result;

    // Reject suspended / banned accounts immediately
    if (user.status === 'BANNED' || user.status === 'INACTIVE') {
      return; // Treat as unauthenticated — route handler will throw FORBIDDEN
    }

    // Slide session expiry if it's within the last 1 day of its window
    const expiresMs =
      typeof session.expires === 'string'
        ? new Date(session.expires).getTime()
        : session.expires.getTime();

    // Cookie sessions slide; bearer sessions do not. Sliding a bearer session
    // would quietly restore the 7-day window we deliberately shortened to 12h.
    const now = Date.now();
    if (extracted.transport === 'cookie' && expiresMs - now < SLIDE_THRESHOLD_MS) {
      const newExpires = new Date(now + SESSION_MAX_AGE_MS);
      touchSession(db, session.id, newExpires).catch((err) => {
        app.log.warn({ err }, 'Failed to slide session expiry — non-fatal');
      });
    }

    // Decorate request.user — this is the ONLY place this gets set.
    // authTransport is set on the same beat, after the session row is verified
    // and the account checked, because the CSRF hook keys its skip off it.
    request.user = {
      id: user.id,
      email: user.email,
      status: user.status,
      emailVerified: user.emailVerified,
      mustChangePassword: user.mustChangePassword,
    };
    request.authTransport = extracted.transport;
    // Read the (possibly just-slid) expiry, not the pre-slide value captured
    // above in `expiresMs` — the slide already happened by this point.
    request.sessionExpiresAt = (
      extracted.transport === 'cookie' && expiresMs - now < SLIDE_THRESHOLD_MS
        ? new Date(now + SESSION_MAX_AGE_MS)
        : session.expires instanceof Date
          ? session.expires
          : new Date(session.expires)
    ).toISOString();

    // Store raw token for signout (needed to call deleteSession with the hash)
    request._rawSessionToken = rawToken;
  });
}

// ─── Guard Helpers ────────────────────────────────────────────────────────────

/**
 * Throws NOT_AUTHENTICATED (401) if request.user is not set.
 * Call at the top of any route handler that requires a valid session.
 *
 * TypeScript assertion: after this call, request.user is non-null.
 */
export function assertAuthenticated(request: FastifyRequest): asserts request is FastifyRequest & {
  user: AuthenticatedUser;
} {
  if (!request.user) {
    throw createDataError('NOT_AUTHENTICATED');
  }
}

/**
 * Set the session cookie on a reply.
 * Always call this after creating a session row in the DB.
 */
export function setSessionCookie(
  reply: import('fastify').FastifyReply,
  rawToken: string,
  config: { isProd: boolean },
): void {
  reply.setCookie(SESSION_COOKIE_NAME, rawToken, {
    httpOnly: true,
    secure: config.isProd,   // Secure in prod/preprod; allows HTTP in local dev
    sameSite: 'lax',         // 'lax' allows cookie on top-level navigations (OAuth redirects)
    path: '/',
    maxAge: SESSION_MAX_AGE_MS / 1000, // seconds
    signed: true,            // @fastify/cookie signs with AUTH_SECRET
  });
}

/**
 * Clear the session cookie on logout.
 */
export function clearSessionCookie(reply: import('fastify').FastifyReply): void {
  reply.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
  reply.clearCookie('csrf_token', { path: '/' });
}
