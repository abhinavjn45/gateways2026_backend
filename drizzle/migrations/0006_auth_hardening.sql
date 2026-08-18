-- Gateways 2026 auth hardening.
--
-- Forward-only and hand-written, like 0002-0005. Do NOT regenerate this with
-- drizzle-kit generate/push: the schema barrel does not cover every live table,
-- so push proposes destructive DROP TABLEs (see drizzle.config.ts).
--
-- Pre-flight before applying anywhere but local:
--   SELECT COUNT(*) FROM payment_receipts p JOIN users u ON u.id = p.user_id
--    WHERE u.email_verified IS NULL;
--   SELECT COUNT(*) FROM teams t JOIN users u ON u.id = t.leader_user_id
--    WHERE u.email_verified IS NULL;
-- Both MUST be 0. payment_receipts.user_id and teams.leader_user_id are
-- ON DELETE NO ACTION, so a stale row holding either aborts step 1 midway.

-- 1. Remove the accounts stranded by the old signup lockout.
--
--    These are accounts where email_verified IS NULL: the OTP could not be
--    delivered, signin refused the unverified user, and signup refused the
--    duplicate address — leaving the address permanently unusable. Nobody ever
--    proved ownership of these addresses, so there is no account here worth
--    preserving; the owners simply sign up again, which now works because
--    accounts are created already-verified.
--
--    profiles, characters, user_roles, sessions and accounts all cascade.
DELETE FROM `users` WHERE `email_verified` IS NULL;
--> statement-breakpoint

-- 2. Retire the Google provider tokens.
--
--    These columns exist in the database but were removed from
--    src/db/schema/auth.ts — silent drift. Nothing in the codebase ever reads
--    them back and nothing refreshes a Google token; the only access_token the
--    app uses is the in-flight one from the token exchange, consumed
--    immediately to fetch userinfo. They are write-only dead weight, and a
--    stored Google refresh token is a standing liability.
ALTER TABLE `accounts` DROP COLUMN `refresh_token`;
--> statement-breakpoint
ALTER TABLE `accounts` DROP COLUMN `access_token`;
--> statement-breakpoint

-- 3. Clear expired one-time codes, including rows orphaned from deleted users
--    (verification_tokens keys on the email string, not a user FK, so step 1
--    does not cascade to them).
DELETE FROM `verification_tokens` WHERE `expires` < now();
--> statement-breakpoint

-- 4. deleteExpiredSessions() runs on every boot and full-scans without this.
CREATE INDEX `sessions_expires_idx` ON `sessions` (`expires`);
