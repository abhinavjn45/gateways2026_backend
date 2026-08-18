/**
 * Auth Domain Schema
 *
 * Tables: users · accounts · sessions · verification_tokens
 *
 * Translated 1:1 from: drizzle/migrations/0000_ambiguous_sauron.sql
 * DO NOT modify column names or constraints without a matching Drizzle migration.
 */

import {
  bigint,
  boolean,
  mysqlTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  varchar,
} from 'drizzle-orm/mysql-core';
import { sql } from 'drizzle-orm';

// ─── Users ────────────────────────────────────────────────────────────────────
// Core identity record. password_hash is null for OAuth-only accounts.
// status: 'ACTIVE' | 'INACTIVE' | 'BANNED'
// emailVerified: null = unverified (manual signup); timestamp = verified
export const users = mysqlTable('users', {
  id: varchar('id', { length: 36 }).primaryKey().notNull(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }),
  status: varchar('status', { length: 32 }).notNull().default('ACTIVE'),
  emailVerified: timestamp('email_verified', { fsp: 3 }),
  mustChangePassword: boolean('must_change_password').notNull().default(false),
  createdAt: timestamp('created_at', { fsp: 3 })
    .notNull()
    .default(sql`(now())`),
  updatedAt: timestamp('updated_at', { fsp: 3 })
    .notNull()
    .default(sql`(now())`)
    .$onUpdate(() => new Date()),
});

// ─── Accounts (OAuth Linked Accounts) ────────────────────────────────────────
// One row per provider per user. provider + providerAccountId must be globally unique.
// refreshToken / accessToken are OAuth provider tokens — NOT our session tokens.
export const accounts = mysqlTable(
  'accounts',
  {
    id: varchar('id', { length: 36 }).primaryKey().notNull(),
    userId: varchar('user_id', { length: 36 })
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    type: varchar('type', { length: 255 }).notNull(),
    provider: varchar('provider', { length: 255 }).notNull(),
    providerAccountId: varchar('provider_account_id', { length: 255 }).notNull(),
    expiresAt: bigint('expires_at', { mode: 'number' }),
    tokenType: varchar('token_type', { length: 255 }),
    scope: varchar('scope', { length: 255 }),
    idToken: text('id_token'),
    sessionState: varchar('session_state', { length: 255 }),
  },
  (table) => ({
    providerAccountIdx: uniqueIndex('provider_providerAccountId_idx').on(
      table.provider,
      table.providerAccountId,
    ),
  }),
);

// ─── Sessions ─────────────────────────────────────────────────────────────────
// One row per active login. sessionToken stores the SHA-256 hash of the raw token
// (raw token lives only in the httpOnly cookie — never stored plaintext in DB).
// expires is updated on every authenticated request (7-day sliding window).
export const sessions = mysqlTable('sessions', {
  id: varchar('id', { length: 36 }).primaryKey().notNull(),
  sessionToken: varchar('session_token', { length: 255 }).notNull().unique(),
  userId: varchar('user_id', { length: 36 })
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  expires: timestamp('expires', { fsp: 3 }).notNull(),
});

// ─── Verification Tokens (Email OTP + Password Reset) ─────────────────────────
// Stores bcrypt-hashed OTPs for email verification and SHA-256 digests for
// password reset links. `purpose` separates the two flows.
// identifier = email address; purpose = 'EMAIL_VERIFICATION' | 'PASSWORD_RESET'
// Rows are consumed after successful verification/reset.
export const verificationTokens = mysqlTable(
  'verification_tokens',
  {
    identifier: varchar('identifier', { length: 255 }).notNull(),
    token: varchar('token', { length: 255 }).notNull().unique(),
    expires: timestamp('expires', { fsp: 3 }).notNull(),
    purpose: varchar('purpose', { length: 64 }).notNull().default('EMAIL_VERIFICATION'),
  },
  (table) => ({
    pk: primaryKey({ columns: [table.identifier, table.token] }),
  }),
);

// ─── Type Exports ─────────────────────────────────────────────────────────────
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Account = typeof accounts.$inferSelect;
export type NewAccount = typeof accounts.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type VerificationToken = typeof verificationTokens.$inferSelect;
export type NewVerificationToken = typeof verificationTokens.$inferInsert;
