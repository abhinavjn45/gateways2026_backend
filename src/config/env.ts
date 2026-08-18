import { z } from 'zod';
import dotenv from 'dotenv';
import path from 'path';

import fs from 'fs';

/**
 * Parse boolean environment variables without the `Boolean("false")` trap.
 *
 * `z.coerce.boolean()` treats every non-empty string as true, so an env value
 * of `SMTP_SECURE=false` previously enabled TLS immediately. Port 587 then
 * received a TLS ClientHello before STARTTLS and Gmail returned "wrong version
 * number".
 */
const booleanEnv = () =>
  z.preprocess((value) => {
    if (typeof value !== 'string') return value;

    switch (value.trim().toLowerCase()) {
      case 'true':
      case '1':
      case 'yes':
      case 'on':
        return true;
      case 'false':
      case '0':
      case 'no':
      case 'off':
        return false;
      default:
        return value;
    }
  }, z.boolean().optional());

// Determine environment file based on NODE_ENV
const nodeEnv = process.env.NODE_ENV || 'development';
const envFile = `.env.${nodeEnv}`;
const envPath = path.resolve(process.cwd(), envFile);

// Load specific environment file if it exists, otherwise fall back to .env
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath, override: true });
} else {
  dotenv.config({ path: path.resolve(process.cwd(), '.env') });
}

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production', 'preproduction']).default('development'),
  PORT: z.coerce.number().default(4000),
  HOST: z.string().default('0.0.0.0'),
  APP_BASE_URL: z.string().url().default('http://localhost:4000'),
  FRONTEND_BASE_URL: z.string().url().default('http://localhost:3000'),
  REGISTRATION_CONSOLE_URL: z.string().url().default('http://localhost:3002'),

  // Individual DB connection variables
  DB_HOST: z.string().optional(),
  DB_PORT: z.coerce.number().default(3306),
  DB_USER: z.string().optional(),
  DB_PASSWORD: z.string().optional(),
  DB_NAME: z.string().optional(),

  // Dual DB URLs (Optional if individual DB_* variables are provided)
  DATABASE_URL: z.string().optional(),
  WRITER_DATABASE_URL: z.string().optional(),

  // Security secrets
  AUTH_SECRET: z.string().min(32, 'AUTH_SECRET must be at least 32 characters long'),
  CHECKIN_TOKEN_SECRET: z.string().min(32, 'CHECKIN_TOKEN_SECRET must be at least 32 characters long'),

  // CORS
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  /**
   * Vercel project slug for the admin dashboard, e.g. `dashboard-inky-kappa-88`.
   * Enables CORS for that project's preview deploys ONLY, and never in
   * production. Leave unset to disable preview access entirely.
   */
  CORS_VERCEL_PROJECT: z.string().optional(),

  /**
   * The one-time entry-pass fee, in rupees. The backend does not record a
   * per-payment amount (one global pass per user), so this is the amount every
   * receipt represents. Configurable rather than hardcoded so a fee change is not
   * a code change.
   */
  ENTRY_PASS_AMOUNT_INR: z.coerce.number().int().positive().default(250),

  // Storage / Mail optional
  SMTP_URL: z.string().optional(),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_SECURE: booleanEnv(),
  SMTP_FROM: z.string().optional(),

  // Fallback SMTP config
  SMTP_FALLBACK_URL: z.string().optional(),
  SMTP_FALLBACK_HOST: z.string().optional(),
  SMTP_FALLBACK_PORT: z.coerce.number().optional(),
  SMTP_FALLBACK_USER: z.string().optional(),
  SMTP_FALLBACK_PASS: z.string().optional(),
  SMTP_FALLBACK_SECURE: booleanEnv(),
  SMTP_FALLBACK_FROM: z.string().optional(),

  STORAGE_BUCKET_URL: z.string().optional(),
  STORAGE_ACCESS_KEY: z.string().optional(),
  STORAGE_SECRET_KEY: z.string().optional(),

  // Google Sheets Integration (Storage Strategy: Sheets is the live source of truth)
  GOOGLE_SERVICE_EMAIL: z.string().optional(),
  GOOGLE_PRIVATE_KEY: z.string().optional(),
  SHEET_ID: z.string().optional(),

  // Webhook shared secret — secures POST /api/webhook/sheet-update
  SHEET_WEBHOOK_SECRET: z.string().optional(),

  // Cloudinary (payment receipt storage)
  CLOUDINARY_CLOUD_NAME: z.string().optional(),
  CLOUDINARY_API_KEY: z.string().optional(),
  CLOUDINARY_API_SECRET: z.string().optional(),

  // Session
  SESSION_MAX_AGE_DAYS: z.coerce.number().default(7),

  /**
   * Gate signup behind an emailed one-time code.
   *
   * OFF by default, and currently off everywhere: SMTP is not provisioned, and
   * a verification step that cannot deliver its code is a permanent lockout —
   * the account is committed, signin refuses an unverified user, and signup
   * refuses a duplicate address. Creating users already-verified removes that
   * failure mode entirely rather than papering over it.
   *
   * The OTP machinery below is still built, tested and reachable, so switching
   * this back on once SMTP exists is a config change, not a code change.
   *
   * Uses booleanEnv() deliberately: z.coerce.boolean() maps the string "false"
   * to true, which would make this flag impossible to turn off from a .env file.
   */
  REQUIRE_EMAIL_VERIFICATION: booleanEnv().default(false),

  // OTP
  OTP_EXPIRY_MINUTES: z.coerce.number().default(15),
  PASSWORD_RESET_EXPIRY_MINUTES: z.coerce.number().int().positive().default(30),

  // Google OAuth (optional — required only if using OAuth sign-in)
  OAUTH_GOOGLE_CLIENT_ID: z.string().optional(),
  OAUTH_GOOGLE_CLIENT_SECRET: z.string().optional(),
  OAUTH_CALLBACK_BASE_URL: z.string().url().optional(),
});

export type AppConfig = z.infer<typeof envSchema>;

let cachedConfig: AppConfig | null = null;

export function loadConfig(): AppConfig {
  if (cachedConfig) {
    return cachedConfig;
  }

  // Pre-process process.env to auto-construct DATABASE_URL if missing
  if (!process.env.DATABASE_URL && process.env.DB_HOST && process.env.DB_USER && process.env.DB_NAME) {
    const host = process.env.DB_HOST;
    const port = process.env.DB_PORT || '3306';
    const user = process.env.DB_USER;
    const pass = encodeURIComponent(process.env.DB_PASSWORD || '');
    const dbName = process.env.DB_NAME;
    process.env.DATABASE_URL = `mysql://${user}:${pass}@${host}:${port}/${dbName}`;
  }

  const result = envSchema.safeParse(process.env);

  if (!result.success || (!result.data.DATABASE_URL && !result.data.DB_HOST)) {
    console.error('❌ Invalid Environment Variables Configuration:');
    if (!result.success) {
      console.error(JSON.stringify(result.error.format(), null, 2));
    } else {
      console.error('Either DATABASE_URL or (DB_HOST, DB_USER, DB_NAME) must be provided.');
    }
    throw new Error('Process initialization failed due to invalid environment variables.');
  }

  cachedConfig = result.data;
  return cachedConfig;
}
