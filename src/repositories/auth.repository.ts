/**
 * Auth Repository
 *
 * All database access for the auth domain (users, sessions, accounts, verification_tokens).
 * Every function accepts a `db` parameter — never calls getAppDb() internally —
 * so callers control which pool is used and can pass a transaction object.
 *
 * Security invariants:
 *   - findUserByEmail / findUserById NEVER return passwordHash to callers.
 *     Internal helpers that need the hash are separate (findUserWithHashByEmail).
 *   - Sessions store the SHA-256 hash of the raw token — not the raw token itself.
 *   - OTPs and reset tokens are stored as one-way hashes — never plaintext.
 */

import { and, eq, lt, sql } from 'drizzle-orm';
import crypto from 'node:crypto';
import { MySql2Database } from 'drizzle-orm/mysql2';
import * as schema from '../db/schema/index.js';
import { accounts, sessions, users, verificationTokens } from '../db/schema/auth.js';
import { profiles, userRoles } from '../db/schema/identity.js';
import { characters } from '../db/schema/characters.js';
import { withTransaction } from '../db/transaction.js';
import { createDataError } from '../errors/DataError.js';
import { ensureDefaultCharacter } from './characters.repository.js';

/**
 * Generate a participant code.
 *
 * Deliberately NOT derived from the user's UUID. This used to slice the first
 * 8 hex characters off a uuidv7 id, but a v7 UUID's leading bits are a
 * millisecond timestamp, not randomness — every id minted in the same ~65s
 * window shares that prefix. Any two people who signed up close together
 * collided on profiles_participant_code_unique and the second one's signup
 * 500'd. random bytes have no such shared structure.
 */
function generateParticipantCode(): string {
  return `GWS26-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

type Db = MySql2Database<typeof schema>;

// ─── Exported User Types ───────────────────────────────────────────────────────

/** Public-safe user object — no passwordHash */
export type PublicUser = Omit<schema.User, 'passwordHash'>;

/** Internal-only user with hash — only used inside signinWithPassword */
export type UserWithHash = schema.User;

// ─── User Queries ─────────────────────────────────────────────────────────────

/**
 * Find a user by email (case-insensitive).
 * Returns public fields only — passwordHash excluded.
 */
export async function findUserByEmail(db: Db, email: string): Promise<PublicUser | null> {
  const rows = await db
    .select({
      id: users.id,
      email: users.email,
      status: users.status,
      emailVerified: users.emailVerified,
      mustChangePassword: users.mustChangePassword,
      createdAt: users.createdAt,
      updatedAt: users.updatedAt,
    })
    .from(users)
    .where(eq(sql`LOWER(${users.email})`, email.toLowerCase()))
    .limit(1);

  return rows[0] ?? null;
}

/**
 * Find a user by email INCLUDING passwordHash.
 * For INTERNAL use by signinWithPassword only — never expose to API callers.
 */
export async function findUserWithHashByEmail(db: Db, email: string): Promise<UserWithHash | null> {
  const rows = await db
    .select()
    .from(users)
    .where(eq(sql`LOWER(${users.email})`, email.toLowerCase()))
    .limit(1);

  return rows[0] ?? null;
}

/**
 * Find a user by ID (public fields only, no passwordHash).
 * Used by the session hook to re-validate the authenticated user.
 */
export async function findUserById(db: Db, id: string): Promise<PublicUser | null> {
  const rows = await db
    .select({
      id: users.id,
      email: users.email,
      status: users.status,
      emailVerified: users.emailVerified,
      mustChangePassword: users.mustChangePassword,
      createdAt: users.createdAt,
      updatedAt: users.updatedAt,
    })
    .from(users)
    .where(eq(users.id, id))
    .limit(1);

  return rows[0] ?? null;
}

/**
 * Create a new user + an empty profile placeholder in a single transaction.
 * passwordHash is null for OAuth users (email-only creation).
 *
 * Returns the created user's ID.
 */
export async function createUser(
  db: Db,
  params: {
    id: string;
    email: string;
    username: string;
    passwordHash?: string;
    fullName?: string;
    mustChangePassword?: boolean;
    /**
     * Verification timestamp, or null to leave the account unverified.
     * Callers decide: signup passes a date when REQUIRE_EMAIL_VERIFICATION is
     * off, null when it is on. Defaults to null so an omission cannot silently
     * mark an account verified.
     */
    emailVerified?: Date | null;
  },
): Promise<string> {
  await withTransaction(db, async (tx) => {
    const username = params.username.trim();
    const existingCharacter = await tx
      .select({ userId: characters.userId })
      .from(characters)
      .where(eq(sql`LOWER(${characters.playerName})`, username.toLowerCase()))
      .limit(1);
    if (existingCharacter[0]) {
      throw createDataError('PLAYER_NAME_TAKEN', 'That username is already taken.');
    }

    await tx.insert(users).values({
      id: params.id,
      email: params.email.toLowerCase(),
      passwordHash: params.passwordHash ?? null,
      status: 'ACTIVE',
      emailVerified: params.emailVerified ?? null,
      mustChangePassword: params.mustChangePassword ?? false,
    });
    await tx.insert(profiles).values({
      userId: params.id,
      participantCode: generateParticipantCode(),
      fullName: params.fullName?.trim() || username,
    });
    await tx.insert(characters).values({
      userId: params.id,
      playerName: username,
      totalXp: 0,
      avatarAssetId: 'prospector',
    });
    await tx.insert(userRoles).values({
      id: crypto.randomUUID(),
      userId: params.id,
      role: 'PARTICIPANT',
      eventScopeId: null,
    });
  });
  return params.id;
}

/**
 * Mark verified AND consume the OTP in one transaction.
 *
 * These were two independent statements fired through Promise.all, which is
 * concurrency, not atomicity: if the consume failed after the mark succeeded,
 * a spent code stayed live until it expired.
 */
export async function verifyEmailAtomically(
  db: Db,
  params: { userId: string; email: string; purpose?: string },
): Promise<void> {
  const purpose = params.purpose ?? 'EMAIL_VERIFICATION';
  await withTransaction(db, async (tx) => {
    await tx.update(users).set({ emailVerified: sql`now()` }).where(eq(users.id, params.userId));
    await tx
      .delete(verificationTokens)
      .where(
        and(
          eq(verificationTokens.identifier, params.email),
          eq(verificationTokens.purpose, purpose),
        ),
      );
  });
}

/**
 * Re-point an existing unverified account at new credentials.
 *
 * Used by the signup re-try path: the address was never verified, so nobody
 * has proven ownership and there is no account worth protecting — overwriting
 * is safer than stranding the address forever behind EMAIL_TAKEN.
 *
 * Single transaction so a taken username cannot leave a rotated password
 * behind on a half-updated account.
 */
export async function resetUserCredentials(
  db: Db,
  params: { userId: string; passwordHash: string; username: string; fullName?: string },
): Promise<void> {
  await withTransaction(db, async (tx) => {
    const username = params.username.trim();

    // Same uniqueness rule as createUser — scoped to OTHER users, so reusing
    // your own existing username on a retry is not a conflict.
    const clash = await tx
      .select({ userId: characters.userId })
      .from(characters)
      .where(eq(sql`LOWER(${characters.playerName})`, username.toLowerCase()))
      .limit(1);
    if (clash[0] && clash[0].userId !== params.userId) {
      throw createDataError('PLAYER_NAME_TAKEN', 'That username is already taken.');
    }

    await tx
      .update(users)
      .set({ passwordHash: params.passwordHash, mustChangePassword: false })
      .where(eq(users.id, params.userId));

    await tx
      .update(characters)
      .set({ playerName: username })
      .where(eq(characters.userId, params.userId));

    if (params.fullName?.trim()) {
      await tx
        .update(profiles)
        .set({ fullName: params.fullName.trim() })
        .where(eq(profiles.userId, params.userId));
    }
  });
}

/**
 * Does this user have a linked OAuth identity?
 *
 * Used to refuse password signup/change on a Google-backed account, so a
 * password can never be grafted onto an identity Google owns.
 */
export async function hasLinkedOAuthAccount(db: Db, userId: string): Promise<boolean> {
  const rows = await db
    .select({ id: accounts.id })
    .from(accounts)
    .where(eq(accounts.userId, userId))
    .limit(1);
  return Boolean(rows[0]);
}

/**
 * Mark a user's email as verified (called after successful OTP verification).
 */
export async function markEmailVerified(db: Db, userId: string): Promise<void> {
  await db
    .update(users)
    .set({ emailVerified: sql`now()` })
    .where(eq(users.id, userId));
}

export async function updatePassword(
  db: Db,
  userId: string,
  passwordHash: string,
): Promise<void> {
  await db
    .update(users)
    .set({ passwordHash, mustChangePassword: false })
    .where(eq(users.id, userId));
}

export async function deleteSessionsForUser(db: Db, userId: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.userId, userId));
}

// ─── Session Queries ──────────────────────────────────────────────────────────

/** Result shape for findSessionByHashedToken — user + session combined */
export interface SessionWithUser {
  session: schema.Session;
  user: PublicUser;
}

/**
 * Look up a session by its hashed token (SHA-256 of the raw cookie value).
 * Joins sessions → users. Returns null if not found or expired.
 */
export async function findSessionByHashedToken(
  db: Db,
  hashedToken: string,
): Promise<SessionWithUser | null> {
  const now = new Date();

  const rows = await db
    .select({
      session: sessions,
      user: {
        id: users.id,
        email: users.email,
        status: users.status,
        emailVerified: users.emailVerified,
        mustChangePassword: users.mustChangePassword,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
      },
    })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(
      and(
        eq(sessions.sessionToken, hashedToken),
        // Filter out expired sessions at query time
        sql`${sessions.expires} > ${now.toISOString()}`,
      ),
    )
    .limit(1);

  if (!rows[0]) return null;

  return {
    session: rows[0].session,
    user: rows[0].user as PublicUser,
  };
}

/**
 * Create a new session row (stores the hashed token — raw token stays in cookie).
 */
export async function createSession(
  db: Db,
  params: { id: string; userId: string; hashedToken: string; expires: Date },
): Promise<void> {
  await db.insert(sessions).values({
    id: params.id,
    sessionToken: params.hashedToken,
    userId: params.userId,
    expires: params.expires,
  });
}

/**
 * Slide the session expiry window forward (called on every valid authenticated request).
 * Only slides if the session is within the last day of its window to avoid
 * hammering the DB on every single request.
 */
export async function touchSession(
  db: Db,
  sessionId: string,
  newExpires: Date,
): Promise<void> {
  await db
    .update(sessions)
    .set({ expires: newExpires })
    .where(eq(sessions.id, sessionId));
}

/**
 * Delete a session row (logout / revocation).
 * Silently succeeds if the token is already gone.
 */
export async function deleteSession(db: Db, hashedToken: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.sessionToken, hashedToken));
}

/**
 * Purge all sessions that have passed their expiry date.
 * Call on server startup and/or periodically to keep the table lean.
 */
export async function deleteExpiredSessions(db: Db): Promise<void> {
  const now = new Date();
  await db.delete(sessions).where(lt(sessions.expires, now));
}

// ─── Verification Token (OTP) Queries ────────────────────────────────────────

/**
 * Upsert a verification token row for an email address.
 * Uses INSERT ... ON DUPLICATE KEY UPDATE to replace any existing OTP
 * (handles "resend OTP" gracefully without a separate delete step).
 */
export async function upsertVerificationToken(
  db: Db,
  params: {
    identifier: string; // email address
    hashedOtp: string;  // bcrypt hash of the 6-digit OTP
    expires: Date;
    purpose?: string;
  },
): Promise<void> {
  const purpose = params.purpose ?? 'EMAIL_VERIFICATION';

  // Delete any existing token for this identifier+purpose before inserting
  // (composite PK is identifier+token, so ON DUPLICATE KEY UPDATE won't cleanly
  // handle purpose-scoped upserts — explicit delete + insert is safer)
  await db
    .delete(verificationTokens)
    .where(
      and(
        eq(verificationTokens.identifier, params.identifier),
        eq(verificationTokens.purpose, purpose),
      ),
    );

  await db.insert(verificationTokens).values({
    identifier: params.identifier,
    token: params.hashedOtp,
    expires: params.expires,
    purpose,
  });
}

/**
 * Find the stored verification token row for a given email + purpose.
 * Returns null if no pending OTP exists.
 */
export async function findVerificationToken(
  db: Db,
  identifier: string,
  purpose: string = 'EMAIL_VERIFICATION',
): Promise<schema.VerificationToken | null> {
  const rows = await db
    .select()
    .from(verificationTokens)
    .where(
      and(
        eq(verificationTokens.identifier, identifier),
        eq(verificationTokens.purpose, purpose),
      ),
    )
    .limit(1);

  return rows[0] ?? null;
}

/**
 * Find a token by its stored digest. Password-reset callers use a random
 * SHA-256 digest here; the raw token is never sent to the database.
 */
export async function findVerificationTokenByToken(
  db: Db,
  hashedToken: string,
  purpose: string,
): Promise<schema.VerificationToken | null> {
  const rows = await db
    .select()
    .from(verificationTokens)
    .where(
      and(
        eq(verificationTokens.token, hashedToken),
        eq(verificationTokens.purpose, purpose),
      ),
    )
    .for('update')
    .limit(1);

  return rows[0] ?? null;
}

/**
 * Delete (consume) a verification token row after successful OTP verification.
 * Call this AFTER the OTP has been verified — part of the atomic verify step.
 */
export async function consumeVerificationToken(
  db: Db,
  identifier: string,
  purpose: string = 'EMAIL_VERIFICATION',
): Promise<void> {
  await db
    .delete(verificationTokens)
    .where(
      and(
        eq(verificationTokens.identifier, identifier),
        eq(verificationTokens.purpose, purpose),
      ),
    );
}

/** Consume exactly one token identified by its stored digest. */
export async function consumeVerificationTokenByToken(
  db: Db,
  hashedToken: string,
  purpose: string,
): Promise<void> {
  await db
    .delete(verificationTokens)
    .where(
      and(
        eq(verificationTokens.token, hashedToken),
        eq(verificationTokens.purpose, purpose),
      ),
    );
}

// ─── OAuth Account Queries ────────────────────────────────────────────────────

/**
 * Find an existing OAuth linked account by provider + providerAccountId.
 * Returns null if this Google account has never signed in before.
 */
export async function findOAuthAccount(
  db: Db,
  provider: string,
  providerAccountId: string,
): Promise<schema.Account | null> {
  const rows = await db
    .select()
    .from(accounts)
    .where(
      and(
        eq(accounts.provider, provider),
        eq(accounts.providerAccountId, providerAccountId),
      ),
    )
    .limit(1);

  return rows[0] ?? null;
}

/**
 * Upsert an OAuth account row (create on first sign-in, update tokens on subsequent sign-ins).
 */
export async function upsertOAuthAccount(
  db: Db,
  params: schema.NewAccount,
): Promise<void> {
  await db
    .insert(accounts)
    .values(params)
    .onDuplicateKeyUpdate({
      set: {
        expiresAt: params.expiresAt,
        idToken: params.idToken,
        scope: params.scope,
        tokenType: params.tokenType,
        sessionState: params.sessionState,
      },
    });
}

/**
 * Atomic find-or-create for Google OAuth sign-in:
 *  1. Check if the OAuth account already exists → return linked userId.
 *  2. If not: check if a user with this email already exists (manual account) → link to it.
 *  3. If not: create a new user (email-unverified, no password) + link the OAuth account.
 *
 * All steps run inside a single transaction.
 * Returns the userId to create a session for.
 */
export async function findOrCreateOAuthUser(
  db: Db,
  params: {
    userId: string;         // pre-generated UUID for potential new user
    accountId: string;      // pre-generated UUID for accounts row
    email: string;
    provider: string;
    providerAccountId: string;
    googleProfile: {
      name?: string;
      picture?: string;
      expiresAt?: number;
      idToken?: string;
      scope?: string;
    };
  },
): Promise<string> {
  return withTransaction(db, async (tx) => {
    // Step 1: existing OAuth account?
    const existingAccount = await findOAuthAccount(tx as Db, params.provider, params.providerAccountId);
    if (existingAccount) {
      // Refresh tokens while we're here
      await upsertOAuthAccount(tx as Db, {
        id: existingAccount.id,
        userId: existingAccount.userId,
        type: 'oauth',
        provider: params.provider,
        providerAccountId: params.providerAccountId,
        expiresAt: params.googleProfile.expiresAt ?? null,
        idToken: params.googleProfile.idToken ?? null,
        scope: params.googleProfile.scope ?? null,
        tokenType: 'Bearer',
        sessionState: null,
      });
      return existingAccount.userId;
    }

    // Step 2: existing user with same email?
    const existingUserRows = await (tx as Db)
      .select({ id: users.id, emailVerified: users.emailVerified, passwordHash: users.passwordHash })
      .from(users)
      .where(eq(sql`LOWER(${users.email})`, params.email.toLowerCase()))
      .limit(1);

    let targetUserId: string;

    if (existingUserRows[0]) {
      const existing = existingUserRows[0];
      targetUserId = existing.id;

      // A VERIFIED existing account linking Google is the legitimate case: its
      // owner already proved the address once (password flow) and is now
      // proving it again (Google), so trust both credentials going forward.
      //
      // An UNVERIFIED existing account is different and dangerous to link
      // blindly. Nobody has proven ownership of that row yet — it could be an
      // attacker's pre-registration of the victim's email address, sitting on
      // a password only the attacker knows (a "pre-hijack" account takeover:
      // register the victim's email first, wait for them to "create" their
      // account via Google, then sign in later with the password already set).
      // Clearing the password before marking verified matches the re-signup
      // path in signupWithPassword — an unverified row's password was never
      // proven by anyone, so it does not get to survive into the account
      // Google just verified.
      if (!existing.emailVerified && existing.passwordHash) {
        await (tx as Db)
          .update(users)
          .set({ passwordHash: null, mustChangePassword: false })
          .where(eq(users.id, targetUserId));
      }
      await markEmailVerified(tx as Db, targetUserId);
    } else {
      // Step 3: brand new user. Google has already verified this email address
      // (checked by the caller before this transaction starts), so it is marked
      // verified immediately — no app-owned OTP round-trip needed.
      await (tx as Db).insert(users).values({
        id: params.userId,
        email: params.email.toLowerCase(),
        passwordHash: null,
        status: 'ACTIVE',
        emailVerified: new Date(),
      });
      await (tx as Db).insert(profiles).values({
        userId: params.userId,
        participantCode: generateParticipantCode(),
        fullName: params.googleProfile.name?.trim() || params.email.split('@')[0],
      });
      await (tx as Db).insert(userRoles).values({
        id: crypto.randomUUID(),
        userId: params.userId,
        role: 'PARTICIPANT',
        eventScopeId: null,
      });
      targetUserId = params.userId;
    }

    // Existing manual accounts linked to Google may not have a character yet.
    // Keep the OAuth path subject to the same default-character invariant.
    await ensureDefaultCharacter(
      tx as Db,
      targetUserId,
      params.googleProfile.name || params.email.split('@')[0],
    );

    // Insert the OAuth account row
    await upsertOAuthAccount(tx as Db, {
      id: params.accountId,
      userId: targetUserId,
      type: 'oauth',
      provider: params.provider,
      providerAccountId: params.providerAccountId,
      expiresAt: params.googleProfile.expiresAt ?? null,
      idToken: params.googleProfile.idToken ?? null,
      scope: params.googleProfile.scope ?? null,
      tokenType: 'Bearer',
      sessionState: null,
    });

    return targetUserId;
  });
}
