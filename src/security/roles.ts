/**
 * RBAC — Role definitions and authorization guard helpers.
 *
 * UserRole enum defines all valid role values stored in `user_roles.role`.
 *
 * assertAuthenticated / assertAdmin / assertOrganizer:
 *   - Always re-derives roles from the database — never trusts a cached claim.
 *   - Called inside route preHandlers, NOT in the global session hook.
 *
 * assertAdmin queries the `user_roles` table (src/db/schema/identity.ts) on
 * every call — always re-derived from the writer DB, never cached.
 */

import type { FastifyRequest } from 'fastify';
import { and, eq } from 'drizzle-orm';
import { createDataError } from '../errors/DataError.js';
import { getWriterDb } from '../db/index.js';
import { userRoles } from '../db/schema/identity.js';
import { getUserRoleAssignments, type RoleAssignment } from '../repositories/user-roles.repository.js';

// ─── Role Enum ────────────────────────────────────────────────────────────────

export const UserRole = {
  PARTICIPANT: 'PARTICIPANT',
  ORGANIZER: 'ORGANIZER',
  SCANNER: 'SCANNER',
  ADMIN: 'ADMIN',
} as const;

export type UserRole = (typeof UserRole)[keyof typeof UserRole];

// ─── assertAuthenticated ──────────────────────────────────────────────────────

/**
 * Re-exported from the session plugin, which owns it.
 *
 * This module used to define a byte-identical second copy. Two guards with the
 * same name and the same job is how they drift: a fix applied to one silently
 * leaves the other in place, and callers cannot tell which they imported. The
 * plugin's copy wins because that is where request.user is set, so the guard
 * and the thing it guards live together.
 */
export { assertAuthenticated } from '../plugins/jwt-auth.js';
import { assertAuthenticated } from '../plugins/jwt-auth.js';

// ─── assertAdmin ──────────────────────────────────────────────────────────────

/**
 * Throws FORBIDDEN (403) if the authenticated user does not hold the ADMIN role.
 * Throws NOT_AUTHENTICATED (401) if there's no session at all.
 * Always re-derives from the database — never trusts a cached/client claim.
 */
export async function assertAdmin(request: FastifyRequest): Promise<void> {
  assertAuthenticated(request);

  const db = getWriterDb();
  const rows = await db
    .select({ id: userRoles.id })
    .from(userRoles)
    .where(and(eq(userRoles.userId, request.user.id), eq(userRoles.role, UserRole.ADMIN)))
    .limit(1);

  if (!rows[0]) {
    throw createDataError('FORBIDDEN', 'Admin role required for this action.');
  }
}

export interface StaffContext {
  assignments: RoleAssignment[];
  isAdmin: boolean;
  organizerEventIds: string[];
  scannerEventIds: string[];
}

/**
 * Resolve staff permissions from the database for this request. This deliberately
 * does not use the session's role payload: revoking an assignment must take
 * effect on the very next protected request.
 */
export async function getStaffContext(request: FastifyRequest): Promise<StaffContext> {
  assertAuthenticated(request);
  const assignments = await getUserRoleAssignments(getWriterDb(), request.user.id);
  const staffAssignments = assignments.filter((assignment) =>
    [UserRole.ADMIN, UserRole.ORGANIZER, UserRole.SCANNER].includes(assignment.role as 'ADMIN' | 'ORGANIZER' | 'SCANNER'),
  );
  if (!staffAssignments.length) {
    throw createDataError('FORBIDDEN', 'Registration console access is required.');
  }
  return {
    assignments: staffAssignments,
    isAdmin: staffAssignments.some((assignment) => assignment.role === UserRole.ADMIN),
    organizerEventIds: staffAssignments
      .filter((assignment) => assignment.role === UserRole.ORGANIZER && assignment.eventScopeId)
      .map((assignment) => assignment.eventScopeId!),
    scannerEventIds: staffAssignments
      .filter((assignment) => assignment.role === UserRole.SCANNER && assignment.eventScopeId)
      .map((assignment) => assignment.eventScopeId!),
  };
}

export async function assertStaff(request: FastifyRequest): Promise<StaffContext> {
  return getStaffContext(request);
}

/**
 * Assert that a staff member can operate on one event. ADMIN is global;
 * ORGANIZER outranks SCANNER when both assignments exist for the event.
 */
export async function assertEventAccess(
  request: FastifyRequest,
  eventId: string,
  minimumRole: 'SCANNER' | 'ORGANIZER' = 'SCANNER',
): Promise<StaffContext> {
  const context = await getStaffContext(request);
  if (context.isAdmin) return context;
  const organizer = context.organizerEventIds.includes(eventId);
  const scanner = context.scannerEventIds.includes(eventId);
  if (organizer || (minimumRole === 'SCANNER' && scanner)) return context;
  throw createDataError('FORBIDDEN', 'You are not assigned to this event.');
}

export async function accessibleEventIds(context: StaffContext, selectedEventId?: string): Promise<string[] | null> {
  if (context.isAdmin) return selectedEventId ? [selectedEventId] : null;
  const ids = [...new Set([...context.organizerEventIds, ...context.scannerEventIds])];
  if (selectedEventId && !ids.includes(selectedEventId)) {
    throw createDataError('FORBIDDEN', 'You are not assigned to this event.');
  }
  return selectedEventId ? [selectedEventId] : ids;
}

// ─── assertOrganizer ──────────────────────────────────────────────────────────

/**
 * Throws FORBIDDEN (403) if the authenticated user is not an organizer for the given event.
 *
 * ⏳ Phase 4 — Requires event_organizers table (events schema).
 */
export async function assertOrganizer(
  request: FastifyRequest,
  eventId: string,
): Promise<void> {
  await assertEventAccess(request, eventId, 'ORGANIZER');
}
