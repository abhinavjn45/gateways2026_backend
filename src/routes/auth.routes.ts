/**
 * Auth Routes
 *
 * Registered under prefix `/auth` in app.ts.
 * Every route uses Zod schemas for validation (via fastify-type-provider-zod).
 *
 * Endpoints:
 *   POST   /auth/signup               — manual registration (no session)
 *   POST   /auth/forgot-password      — email a single-use reset link
 *   POST   /auth/reset-password       — consume reset link and set password
 *   POST   /auth/verify-email         — OTP verification → issues session
 *   POST   /auth/signin               — password login → issues session
 *   POST   /auth/signout              — revoke every session (website + console) + clear cookies  [auth required]
 *   GET    /auth/session              — return current user             [auth required]
 *   GET    /auth/signin/google        — redirect to Google OAuth
 *   GET    /auth/callback/google      — Google OAuth callback → issues session directly
 *   POST   /auth/admin/roles/:userId  — grant role                      [auth + ADMIN]
 *   POST   /auth/console-handoff      — website → console handoff       [auth required]
 *   POST   /auth/console-handoff/exchange — exchange console handoff (bearer)
 *   POST   /auth/website-handoff      — console → website handoff       [auth required]
 *   POST   /auth/website-handoff/exchange — exchange website handoff (cookie)
 *
 * IDOR invariant: userId is ALWAYS derived from request.user (session-validated),
 * never from request body or query params.
 *
 * CSRF: signup, signin, forgot-password, and reset-password are exempt (no
 * session is required). All other POST endpoints require X-CSRF-Token header.
 */

import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { and, eq, isNull } from 'drizzle-orm';
import { v7 as uuidv7 } from 'uuid';
import {
  changePassword,
  createConsoleHandoff,
  exchangeConsoleHandoff,
  createWebsiteHandoff,
  exchangeWebsiteHandoff,
  requestPasswordReset,
  resetPassword,
  getSession,
  handleGoogleCallback,
  initiateGoogleOAuth,
  resolveRequestedTransport,
  resendVerificationCode,
  signinWithPassword,
  signupWithPassword,
  signoutEverywhere,
  verifyEmail,
} from '../services/auth.service.js';
import { assertAuthenticated } from '../plugins/jwt-auth.js';
import { assertAdmin } from '../security/roles.js';
import { getUserRoleAssignments } from '../repositories/user-roles.repository.js';
import { getAppDb, getWriterDb } from '../db/index.js';
import { users } from '../db/schema/auth.js';
import { events } from '../db/schema/events.js';
import { userRoles } from '../db/schema/identity.js';
import { createDataError } from '../errors/DataError.js';
import type { AppConfig } from '../config/env.js';
import {
  GoogleCallbackQuerySchema,
  GoogleOAuthInitQuerySchema,
  GrantRoleBodySchema,
  GrantRoleResponseSchema,
  GoogleOAuthInitResponseSchema,
  ChangePasswordBodySchema,
  ConsoleExchangeBodySchema,
  ConsoleHandoffBodySchema,
  ForgotPasswordBodySchema,
  PasswordResetResponseSchema,
  ResetPasswordBodySchema,
  SessionResponseSchema,
  ResendVerificationBodySchema,
  ResendVerificationResponseSchema,
  SigninBodySchema,
  SigninResponseSchema,
  SignoutResponseSchema,
  SignupBodySchema,
  SignupResponseSchema,
  UserIdParamSchema,
  VerifyEmailBodySchema,
  VerifyEmailResponseSchema,
} from '../schemas/auth.schemas.js';

// ─── Shared Error Response Schema ─────────────────────────────────────────────

const ErrorResponseSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    statusCode: z.number(),
    retryable: z.boolean(),
    correlationId: z.string().optional(),
    details: z.record(z.string(), z.unknown()).optional(),
  }),
});

// ─── Route Registration ────────────────────────────────────────────────────────

export async function registerAuthRoutes(app: FastifyInstance, config: AppConfig) {
  const router = app.withTypeProvider<ZodTypeProvider>();

  // ── POST /auth/signup ──────────────────────────────────────────────────────
  router.post(
    '/signup',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Register a new account (manual / password)',
        description:
          'Creates a new user account. With REQUIRE_EMAIL_VERIFICATION off (current default) ' +
          'the account is created verified and a session is issued with this response ' +
          '(status ACTIVE). With the flag on, a 6-digit OTP is sent instead and the caller ' +
          'must complete POST /auth/verify-email before signing in.',
        body: SignupBodySchema,
        response: {
          201: SignupResponseSchema,
          400: ErrorResponseSchema,
          409: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      // reply is handed down so the service can set the session cookie itself;
      // transport mirrors signin so a bearer client gets a token, not a cookie.
      const result = await signupWithPassword(
        request.body,
        config,
        reply,
        resolveRequestedTransport(request),
      );
      return reply.status(201).send(result);
    },
  );

  router.post(
    '/resend-verification',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Resend an email verification code',
        body: ResendVerificationBodySchema,
        response: {
          200: ResendVerificationResponseSchema,
          400: ErrorResponseSchema,
          503: ErrorResponseSchema,
        },
      },
    },
    async (request) => resendVerificationCode(request.body.email, config),
  );

  // ── POST /auth/forgot-password ───────────────────────────────────────────
  router.post(
    '/forgot-password',
    {
      config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
      schema: {
        tags: ['Authentication'],
        summary: 'Request a password reset link',
        description:
          'Always returns the same response whether or not the email exists. ' +
          'A valid, single-use link is sent only for active password-backed accounts.',
        body: ForgotPasswordBodySchema,
        response: {
          200: PasswordResetResponseSchema,
          400: ErrorResponseSchema,
        },
      },
    },
    async (request) => requestPasswordReset(request.body.email, config),
  );

  // ── POST /auth/reset-password ────────────────────────────────────────────
  router.post(
    '/reset-password',
    {
      config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
      schema: {
        tags: ['Authentication'],
        summary: 'Set a new password from a reset link',
        body: ResetPasswordBodySchema,
        response: {
          200: PasswordResetResponseSchema,
          400: ErrorResponseSchema,
          401: ErrorResponseSchema,
        },
      },
    },
    async (request) => resetPassword(request.body.token, request.body.newPassword),
  );

  // ── POST /auth/verify-email ───────────────────────────────────────────────
  router.post(
    '/verify-email',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Verify email with OTP and receive session cookie',
        description:
          'Validates the 6-digit OTP sent during signup. On success, marks email as verified, ' +
          'issues an httpOnly __session cookie and a readable csrf_token cookie. ' +
          'The user is immediately logged in after this call.',
        body: VerifyEmailBodySchema,
        response: {
          200: VerifyEmailResponseSchema,
          400: ErrorResponseSchema,
          401: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const result = await verifyEmail(
        request.body,
        reply,
        config,
        resolveRequestedTransport(request),
      );
      return reply.send(result);
    },
  );

  // ── POST /auth/signin ──────────────────────────────────────────────────────
  router.post(
    '/signin',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Sign in with email and password',
        description:
          'Authenticates a user with email + password. On success, issues an httpOnly ' +
          '__session cookie (7-day sliding window) and a readable csrf_token cookie. ' +
          'Returns 401 on invalid credentials — user existence is never revealed.',
        body: SigninBodySchema,
        response: {
          200: SigninResponseSchema,
          400: ErrorResponseSchema,
          401: ErrorResponseSchema,
          403: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const result = await signinWithPassword(
        request.body,
        reply,
        config,
        resolveRequestedTransport(request),
      );
      return reply.send(result);
    },
  );

  // ── POST /auth/signout ─────────────────────────────────────────────────────
  // CSRF protected (enforced globally in security.ts)
  router.post(
    '/signout',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Sign out and revoke every session',
        description:
          'Revokes every server-side session for this user (website cookie session AND any ' +
          'registration-console bearer session) and clears the website auth cookies. Requires a ' +
          'valid __session cookie. Idempotent — safe to call even if already signed out.',
        response: {
          200: SignoutResponseSchema,
          401: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      await signoutEverywhere(request, reply);
      return reply.send({ message: 'Signed out everywhere.' });
    },
  );

  // ── GET /auth/session ──────────────────────────────────────────────────────
  router.get(
    '/session',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Get current authenticated user',
        description:
          'Returns the user object for the currently authenticated session. ' +
          'Returns 401 if no valid session cookie is present.',
        response: {
          200: SessionResponseSchema,
          401: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const user = getSession(request);
      return reply.send({
        expiresAt: request.sessionExpiresAt,
        user: {
          id: user.id,
          email: user.email,
          status: user.status,
          emailVerified: user.emailVerified
            ? (typeof user.emailVerified === 'string'
                ? user.emailVerified
                : (user.emailVerified as Date).toISOString())
            : null,
          mustChangePassword: user.mustChangePassword,
        },
        roles: (await getUserRoleAssignments(getAppDb(), user.id)).map((assignment) => ({
          role: assignment.role,
          eventScopeId: assignment.eventScopeId,
        })),
      });
    },
  );

  router.post(
    '/change-password',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Change a password, including an admin-issued temporary password',
        body: ChangePasswordBodySchema,
        response: {
          200: SigninResponseSchema,
          400: ErrorResponseSchema,
          401: ErrorResponseSchema,
          403: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => reply.send(await changePassword(request, reply, config, request.body)),
  );

  router.post(
    '/console-handoff',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Create a one-time handoff into the registration console',
        body: ConsoleHandoffBodySchema,
        response: {
          200: z.object({ url: z.string().url(), expiresAt: z.string() }),
          401: ErrorResponseSchema,
          403: ErrorResponseSchema,
        },
      },
    },
    async (request) => createConsoleHandoff(request, config, request.body.returnTo ?? '/'),
  );

  router.post(
    '/console-handoff/exchange',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Exchange a one-time console handoff for a bearer session',
        body: ConsoleExchangeBodySchema,
        response: {
          200: z.object({
            token: z.string(),
            expiresAt: z.string(),
            returnTo: z.string(),
            user: z.object({
              id: z.string(),
              email: z.string(),
              status: z.string(),
              mustChangePassword: z.boolean(),
            }),
            roles: z.array(z.object({ role: z.string(), eventScopeId: z.string().nullable() })),
          }),
          400: ErrorResponseSchema,
          401: ErrorResponseSchema,
          403: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => reply.send(await exchangeConsoleHandoff(request.body.code, reply, config)),
  );

  // The reverse of console-handoff: a signed-in console user (bearer session)
  // hands their session back to the website (cookie session). Requires only
  // authentication, not staff role — any account that reached the console can
  // return to the participant site.
  router.post(
    '/website-handoff',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Create a one-time handoff from the console back to the website',
        body: ConsoleHandoffBodySchema,
        response: {
          200: z.object({ url: z.string().url(), expiresAt: z.string() }),
          401: ErrorResponseSchema,
        },
      },
    },
    async (request) => createWebsiteHandoff(request, config, request.body.returnTo ?? '/'),
  );

  router.post(
    '/website-handoff/exchange',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Exchange a one-time website handoff for a cookie session',
        body: ConsoleExchangeBodySchema,
        response: {
          200: z.object({
            expiresAt: z.string(),
            returnTo: z.string(),
            user: z.object({
              id: z.string(),
              email: z.string(),
              status: z.string(),
              mustChangePassword: z.boolean(),
            }),
          }),
          400: ErrorResponseSchema,
          401: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => reply.send(await exchangeWebsiteHandoff(request.body.code, reply, config)),
  );

  // ── GET /auth/signin/google ────────────────────────────────────────────────
  router.get(
    '/signin/google',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Initiate Google OAuth sign-in',
        description:
          'Returns the Google OAuth authorization URL. The frontend should redirect the user to this URL.',
        response: {
          200: GoogleOAuthInitResponseSchema,
          500: ErrorResponseSchema,
        },
        querystring: GoogleOAuthInitQuerySchema,
      },
    },
    async (request, reply) => {
      const result = initiateGoogleOAuth(
        config,
        reply,
        request.query.returnTo,
        request.query.client,
      );
      return reply.send(result);
    },
  );

  // ── GET /auth/callback/google ──────────────────────────────────────────────
  router.get(
    '/callback/google',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Google OAuth callback handler',
        description:
          'Receives the authorization code from Google, exchanges it for tokens, ' +
          'finds or creates the user account, and issues a session immediately — ' +
          'Google has already verified the email address, so no app-owned OTP step runs.',
        querystring: GoogleCallbackQuerySchema,
        response: {
          200: SigninResponseSchema,
          400: ErrorResponseSchema,
          401: ErrorResponseSchema,
          500: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { code, error, state } = request.query;

      if (error || !code) {
        throw {
          statusCode: 400,
          message: error ?? 'Google OAuth denied or missing authorization code.',
        };
      }

      const result = await handleGoogleCallback(code, request, reply, config, state);
      // Console flow: no cookie was set on this response, redirectUrl carries a
      // one-time handoff code the console exchanges for its own bearer token.
      if (result.redirectUrl) {
        return reply.redirect(result.redirectUrl, 303);
      }
      // Website flow: the cookie is already set on this response. Redirect so
      // the user lands back in the app instead of seeing the raw JSON response.
      return reply.redirect(`${config.FRONTEND_BASE_URL.replace(/\/$/, '')}${result.returnTo}`, 303);
    },
  );

  // ── POST /auth/admin/roles/:userId ────────────────────────────────────────
  // CSRF protected (enforced globally in security.ts). Kept as a compatibility
  // endpoint for existing operator tooling; the console's richer assignment
  // APIs live under /admin/staff and enforce event scopes there.
  router.post(
    '/admin/roles/:userId',
    {
      schema: {
        tags: ['Admin'],
        summary: 'Grant a role to a user (Admin only)',
        description:
          'Assigns a role to a user. Requires ADMIN role. ' +
          'For event-scoped roles (ORGANIZER, SCANNER), provide eventScopeId.',
        params: UserIdParamSchema,
        body: GrantRoleBodySchema,
        response: {
          200: GrantRoleResponseSchema,
          401: ErrorResponseSchema,
          403: ErrorResponseSchema,
        },
      },
    },
    async (request) => {
      assertAuthenticated(request);
      await assertAdmin(request);

      const userId = request.params.userId;
      const role = request.body.role;
      const eventScopeId = request.body.eventScopeId ?? null;
      if (role === 'ADMIN' && eventScopeId) {
        throw createDataError('VALIDATION_FAILED', 'ADMIN assignments are global and cannot have an event scope.');
      }
      if (['ORGANIZER', 'SCANNER'].includes(role) && !eventScopeId) {
        throw createDataError('VALIDATION_FAILED', `${role} assignments require an event.`);
      }
      const db = getWriterDb();
      const target = await db.select({ id: users.id }).from(users).where(eq(users.id, userId)).limit(1);
      if (!target[0]) throw createDataError('NOT_FOUND', 'User not found.');
      if (eventScopeId) {
        const event = await db.select({ id: events.id }).from(events).where(eq(events.id, eventScopeId)).limit(1);
        if (!event[0]) throw createDataError('NOT_FOUND', 'Assigned event does not exist.');
      }
      const existing = await db.select({ id: userRoles.id }).from(userRoles).where(and(
        eq(userRoles.userId, userId),
        eq(userRoles.role, role),
        eventScopeId ? eq(userRoles.eventScopeId, eventScopeId) : isNull(userRoles.eventScopeId),
      )).limit(1);
      if (!existing[0]) {
        await db.insert(userRoles).values({ id: uuidv7(), userId, role, eventScopeId, grantedBy: request.user.id });
      }
      return { message: 'Role assignment saved.' };
    },
  );
}
