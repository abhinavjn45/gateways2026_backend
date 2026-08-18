/**
 * Admin authentication — registered under `/api/v1/admin/auth`.
 *
 * A separate door from participant signin, checking the ADMIN role BEFORE any
 * session row is created. A non-admin who tries to log into the dashboard gets a
 * 403 and no credential at all, rather than a working token that mysteriously
 * bounces off every page.
 *
 * This is UX and defence in depth — NOT authorization. Every admin route still
 * calls assertAdmin, which re-derives the role from the writer DB on each
 * request, so revoking someone's ADMIN row locks them out immediately instead of
 * at token expiry. Do not "optimize" that away by trusting this login check.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AppConfig } from '../../config/env.js';
import { assertAuthenticated } from '../../plugins/jwt-auth.js';
import { ANONYMOUS_ACTOR, auditRequest } from '../../repositories/audit-log.repository.js';
import { findUserByEmail, findUserById } from '../../repositories/auth.repository.js';
import { getUserRoles } from '../../repositories/user-roles.repository.js';
import { getAppDb } from '../../db/index.js';
import { createDataError } from '../../errors/DataError.js';
import { assertStaff, UserRole } from '../../security/roles.js';
import { getUserRoleAssignments } from '../../repositories/user-roles.repository.js';
import {
  issueSessionFor,
  resolveRequestedTransport,
  signoutEverywhere,
  verifyPasswordCredentials,
} from '../../services/auth.service.js';
import {
  SigninBodySchema,
  SigninResponseSchema,
  AdminSigninResponseSchema,
} from '../../schemas/auth.schemas.js';

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

const AdminSessionResponseSchema = z.object({
  user: z.object({
    id: z.string(),
    email: z.string(),
    status: z.string(),
    emailVerified: z.string().nullable(),
    mustChangePassword: z.boolean(),
  }),
  roles: z.array(z.object({ role: z.string(), eventScopeId: z.string().nullable() })),
});

/**
 * Record a failed sign-in.
 *
 * Attribution differs by case on purpose. When the address matches an account the
 * row is attributed to that user, which is what makes "five failed attempts
 * against this account" answerable. When it matches nothing there is no user to
 * point at, so the row uses the anonymous sentinel and keeps the attempted
 * address as the target — that is the shape that reveals enumeration sweeps.
 *
 * Only the address, a fixed reason and the source IP are recorded. The submitted
 * password must never reach this table.
 */
async function auditSigninFailure(
  request: FastifyRequest,
  email: string,
  reason: 'invalid_credentials',
): Promise<void> {
  const existing = await findUserByEmail(getAppDb(), email.toLowerCase().trim());
  await auditRequest(request, {
    action: 'admin_signin_failed',
    targetType: existing ? 'user' : 'email',
    targetId: existing ? existing.id : email.toLowerCase().trim(),
    actorUserId: existing ? existing.id : ANONYMOUS_ACTOR,
    metadata: { reason: existing ? reason : 'unknown_email', ip: request.ip },
  });
}

export async function registerAdminAuthRoutes(app: FastifyInstance, config: AppConfig) {
  const router = app.withTypeProvider<ZodTypeProvider>();

  router.post(
    '/signin',
    {
      // Admin credentials are the highest-value target in the system and there are
      // only a handful of legitimate holders, so this gets a tighter bucket than
      // the global 100/min.
      config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
      schema: {
        tags: ['Admin · Auth'],
        summary: 'Sign in to the admin dashboard (ADMIN role required)',
        description:
          'Verifies the ADMIN role before creating a session, so non-admins never ' +
          'receive a credential. Send `X-Auth-Transport: bearer` to receive a token ' +
          'in the response body instead of a cookie (required for cross-origin clients).',
        body: SigninBodySchema,
        response: {
          200: AdminSigninResponseSchema,
          401: ErrorResponseSchema,
          403: ErrorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const db = getAppDb();

      // Order matters. Verify credentials, THEN check the role, and only then
      // issue a session — so a non-admin with a correct password leaves no
      // session row behind. Verifying first also keeps "wrong password" and
      // "not an admin" indistinguishable to anyone probing for admin accounts.
      let user;
      try {
        user = await verifyPasswordCredentials(request.body);
      } catch (error) {
        await auditSigninFailure(request, request.body.email, 'invalid_credentials');
        throw error;
      }

      // Any staff role opens this door, not ADMIN alone. The dashboard signs in
      // here directly now, and it is built for all three: ORGANIZER maps to
      // "coordinator" and SCANNER to "desk" in its own role model. Gating on
      // ADMIN would lock out the people who actually work the desk.
      //
      // This deliberately matches GET /admin/auth/session, which has always
      // admitted the same set via assertStaff — the two were inconsistent, so a
      // staff member could hold a valid session this route refused to issue.
      const STAFF_ROLES: readonly string[] = [
        UserRole.ADMIN,
        UserRole.ORGANIZER,
        UserRole.SCANNER,
      ];

      const roles = await getUserRoles(db, user.id);
      if (!roles.some((role) => STAFF_ROLES.includes(role))) {
        await auditRequest(request, {
          action: 'admin_signin_failed',
          targetType: 'user',
          targetId: user.id,
          actorUserId: user.id,
          metadata: { reason: 'not_staff', ip: request.ip },
        });
        throw createDataError('FORBIDDEN', 'This account does not have console access.');
      }

      // Read before the session exists so the dashboard can branch straight to
      // its set-password screen without a second round-trip.
      const account = await findUserById(db, user.id);
      const mustChangePassword = account?.mustChangePassword ?? false;

      const credentials = await issueSessionFor(
        user.id,
        reply,
        config,
        resolveRequestedTransport(request),
      );

      // request.user is not populated on the signin request itself, so the actor
      // is passed explicitly — it is only known once credentials resolve.
      await auditRequest(request, {
        action: 'admin_signin_succeeded',
        targetType: 'user',
        targetId: user.id,
        actorUserId: user.id,
        metadata: { ip: request.ip },
      });

      return reply.send({
        user: { ...user, mustChangePassword },
        ...(credentials ?? {}),
      });
    },
  );

  router.get(
    '/session',
    {
      schema: {
        tags: ['Admin · Auth'],
        summary: 'Current admin user and their roles',
        response: { 200: AdminSessionResponseSchema, 401: ErrorResponseSchema },
      },
    },
    async (request) => {
      assertAuthenticated(request);
      await assertStaff(request);
      const roles = await getUserRoleAssignments(getAppDb(), request.user.id);
      return {
        user: {
          id: request.user.id,
          email: request.user.email,
          status: request.user.status,
          emailVerified:
            request.user.emailVerified == null
              ? null
              : typeof request.user.emailVerified === 'string'
                ? request.user.emailVerified
                : request.user.emailVerified.toISOString(),
          mustChangePassword: request.user.mustChangePassword,
        },
        roles: roles
          .filter((assignment) => [UserRole.ADMIN, UserRole.ORGANIZER, UserRole.SCANNER].includes(assignment.role as any))
          .map((assignment) => ({ role: assignment.role, eventScopeId: assignment.eventScopeId })),
      };
    },
  );

  router.post(
    '/signout',
    {
      schema: {
        tags: ['Admin · Auth'],
        summary: 'Revoke the current admin session',
        response: { 200: z.object({ message: z.string() }), 401: ErrorResponseSchema },
      },
    },
    async (request, reply) => {
      // Captured before the session is destroyed — afterwards request.user is gone.
      const actorUserId = request.user?.id;
      await signoutEverywhere(request, reply);
      if (actorUserId) {
        await auditRequest(request, {
          action: 'admin_signed_out',
          targetType: 'user',
          targetId: actorUserId,
          actorUserId,
        });
      }
      return reply.send({ message: 'Signed out.' });
    },
  );
}
