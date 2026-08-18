/**
 * Auth Zod Schemas
 *
 * All request body, param, query, and response schemas for auth endpoints.
 * Schemas use .strip() implicitly (Zod v4 default) to reject unexpected fields.
 *
 * Import pattern for routes:
 *   import { SignupBodySchema, ... } from '../schemas/auth.schemas.js';
 */

import { z } from 'zod';

// ─── Request Body Schemas ──────────────────────────────────────────────────────

export const SignupBodySchema = z.object({
  email: z
    .string()
    .email('Must be a valid email address.')
    .max(255, 'Email must not exceed 255 characters.'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters.')
    .max(72, 'Password must not exceed 72 characters.'), // bcrypt processes max 72 bytes
  username: z
    .string()
    .trim()
    .min(3, 'Username must be at least 3 characters.')
    .max(16, 'Username must be 16 characters or fewer.')
    .regex(/^[A-Za-z0-9_]+$/, 'Username may contain only letters, numbers, and underscores.'),
  // Kept optional for trusted API clients that still collect a legal name at
  // signup. The participant details form remains the source of truth for it.
  fullName: z.string().trim().min(2).max(255).optional(),
});

export const VerifyEmailBodySchema = z.object({
  email: z.string().email('Must be a valid email address.'),
  otp: z
    .string()
    .length(6, 'OTP must be exactly 6 digits.')
    .regex(/^\d{6}$/, 'OTP must be a 6-digit number.'),
});

export const SigninBodySchema = z.object({
  email: z.string().email('Must be a valid email address.').max(255),
  password: z.string().min(1, 'Password is required.').max(72),
});

export const ChangePasswordBodySchema = z.object({
  currentPassword: z.string().min(1).max(72),
  newPassword: z.string().min(8).max(72),
});

export const ConsoleHandoffBodySchema = z.object({
  returnTo: z.string().regex(/^\/(?!\/)/).max(200).optional(),
});

export const ConsoleExchangeBodySchema = z.object({
  code: z.string().min(32).max(256),
});

export const GrantRoleBodySchema = z.object({
  role: z.enum(['PARTICIPANT', 'ORGANIZER', 'SCANNER', 'ADMIN']),
  // Canonical event IDs are stable catalogue keys (for example
  // `evt-hack-24`), not necessarily UUIDs.
  eventScopeId: z.string().min(1).max(36).optional(),
});

export const GoogleCallbackQuerySchema = z.object({
  code: z.string().min(1, 'Authorization code is required.'),
  state: z.string().optional(),
  error: z.string().optional(),
});

export const GoogleOAuthInitQuerySchema = z.object({
  returnTo: z.string().regex(/^\/(?!\/)/).max(200).optional(),
  /** 'console' routes the callback to the registration console instead of the website. */
  client: z.enum(['website', 'console']).optional(),
});

export const UserIdParamSchema = z.object({
  userId: z.string().uuid('userId must be a valid UUID.'),
});

// ─── Response Schemas ─────────────────────────────────────────────────────────

/** Public user shape returned to clients — never includes passwordHash */
export const PublicUserSchema = z.object({
  id: z.string(),
  email: z.string(),
  status: z.string(),
  emailVerified: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/**
 * Bearer credentials, present only when the caller sent `X-Auth-Transport: bearer`
 * (admin dashboard, mobile). Cookie callers get neither field — the token stays in
 * the httpOnly Set-Cookie header and never enters a JS-readable body.
 *
 * These must be declared here: the Zod serializer strips any field absent from the
 * response schema, so an undeclared token would be silently dropped.
 */
const BearerCredentialFields = {
  token: z.string().optional(),
  expiresAt: z.string().optional(),
};

/**
 * NOTE: the Zod serializer DROPS any field absent from this schema, silently and
 * with no error. Every field signupWithPassword returns must be declared here or
 * it will not reach the client.
 */
export const SignupResponseSchema = z.object({
  /**
   * ACTIVE means a session was issued with this response — the caller is signed
   * in and must not be sent to a verification screen. The two VERIFICATION_*
   * values distinguish "code sent" from "code could NOT be sent", so the UI can
   * stop claiming a delivery that did not happen.
   */
  status: z.enum(['ACTIVE', 'VERIFICATION_SENT', 'VERIFICATION_PENDING']),
  message: z.string(),
  user: z
    .object({
      id: z.string(),
      email: z.string(),
    })
    .optional(),
  ...BearerCredentialFields,
});

export const ResendVerificationBodySchema = z.object({
  email: z.string().email('Must be a valid email address.'),
});

export const ForgotPasswordBodySchema = z.object({
  email: z.string().email('Must be a valid email address.').max(255),
});

export const ResetPasswordBodySchema = z.object({
  token: z
    .string()
    .length(64, 'Reset token is invalid.')
    .regex(/^[a-f0-9]+$/i, 'Reset token is invalid.'),
  newPassword: z
    .string()
    .min(8, 'Password must be at least 8 characters.')
    .max(72, 'Password must not exceed 72 characters.'),
});

export const ResendVerificationResponseSchema = z.object({
  message: z.string(),
});

export const PasswordResetResponseSchema = z.object({
  message: z.string(),
});


export const VerifyEmailResponseSchema = z.object({
  message: z.string(),
  user: z.object({
    id: z.string(),
    email: z.string(),
  }),
  ...BearerCredentialFields,
});

export const SigninResponseSchema = z.object({
  user: z.object({
    id: z.string(),
    email: z.string(),
  }),
  ...BearerCredentialFields,
});

/**
 * Admin/console signin response.
 *
 * Separate from SigninResponseSchema on purpose: that one is shared by
 * /auth/signin, /auth/change-password and the Google callback, so adding
 * mustChangePassword there would publish account state onto three participant
 * routes that have no business carrying it.
 */
export const AdminSigninResponseSchema = z.object({
  user: z.object({
    id: z.string(),
    email: z.string(),
    mustChangePassword: z.boolean(),
  }),
  ...BearerCredentialFields,
});

export const SessionResponseSchema = z.object({
  user: z.object({
    id: z.string(),
    email: z.string(),
    status: z.string(),
    emailVerified: z.string().nullable(),
    mustChangePassword: z.boolean(),
  }),
  roles: z.array(z.object({
    role: z.string(),
    eventScopeId: z.string().nullable(),
  })),
  /** The session's real expiry, from the DB row — not a client-side guess. */
  expiresAt: z.string().optional(),
});

export const SignoutResponseSchema = z.object({
  message: z.string(),
});

export const GoogleOAuthInitResponseSchema = z.object({
  url: z.string().url(),
});

export const GrantRoleResponseSchema = z.object({
  message: z.string(),
});

// ─── Inferred Types ───────────────────────────────────────────────────────────

export type SignupBody = z.infer<typeof SignupBodySchema>;
export type VerifyEmailBody = z.infer<typeof VerifyEmailBodySchema>;
export type SigninBody = z.infer<typeof SigninBodySchema>;
export type ChangePasswordBody = z.infer<typeof ChangePasswordBodySchema>;
export type GrantRoleBody = z.infer<typeof GrantRoleBodySchema>;
export type GoogleCallbackQuery = z.infer<typeof GoogleCallbackQuerySchema>;
export type UserIdParam = z.infer<typeof UserIdParamSchema>;
