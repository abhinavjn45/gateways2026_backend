import dns from 'node:dns';
import net from 'node:net';
import nodemailer, { Transporter } from 'nodemailer';
import { loadConfig, AppConfig } from '../config/env.js';

export interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
  /**
   * The bare code, when this email carries one.
   *
   * Only used by the HTTP relay, which also receives it as a top-level `otp`
   * field so a PHP script written against the older `{ email, otp }` contract
   * keeps working unchanged. SMTP ignores it entirely.
   */
  otp?: string;
}

export interface EmailVerificationOptions {
  to: string;
  verificationToken: string;
  verificationUrl?: string;
}

export interface PasswordResetEmailOptions {
  to: string;
  resetUrl: string;
  expiryMinutes: number;
}

/**
 * Open an SMTP socket using an IPv4 address resolved from the configured host.
 *
 * Some machines advertise an IPv6 interface but have no usable IPv6 route. In
 * that situation Nodemailer's normal dual-stack selection can choose an AAAA
 * record and fail with `EHOSTUNREACH` before it ever tries Gmail's IPv4
 * address. The socket still keeps the original hostname in the transport
 * options, so STARTTLS/SNI uses `smtp.gmail.com`, not the numeric address.
 */
function getIpv4Socket(
  options: { host?: string; port?: number; localAddress?: string },
  callback: (error: Error | null, socketOptions: { connection: net.Socket } | false) => void,
): void {
  const host = options.host;
  if (!host || net.isIP(host)) {
    callback(null, false);
    return;
  }

  dns.resolve4(host, (resolveError, addresses) => {
    if (resolveError || !addresses.length) {
      callback(resolveError ?? new Error(`No IPv4 address found for ${host}`), false);
      return;
    }

    let addressIndex = 0;
    let lastError: Error | null = null;

    const connectNext = () => {
      const address = addresses[addressIndex++];
      if (!address) {
        callback(lastError ?? new Error(`Could not connect to ${host} over IPv4`), false);
        return;
      }

      const socket = net.connect({
        host: address,
        port: options.port ?? 587,
        localAddress: options.localAddress,
      });

      const onError = (error: Error) => {
        lastError = error;
        socket.removeListener('connect', onConnect);
        socket.destroy();
        connectNext();
      };
      const onConnect = () => {
        socket.removeListener('error', onError);
        callback(null, { connection: socket });
      };

      socket.once('error', onError);
      socket.once('connect', onConnect);
    };

    connectNext();
  });
}

class EmailService {
  private primaryTransporter: Transporter | null = null;
  private fallbackTransporter: Transporter | null = null;
  private config: AppConfig;

  constructor() {
    this.config = loadConfig();
    this.initTransporters();
  }

  private initTransporters(): void {
    // Helper to create transport config from URL or host/port/auth params
    const createTransportConfig = (
      url?: string,
      host?: string,
      port?: number,
      user?: string,
      pass?: string,
      secure?: boolean
    ) => {
      if (url) {
        return url;
      }
      if (host) {
        const smtpPort = port || 587;
        return {
          host,
          port: smtpPort,
          secure: secure ?? (smtpPort === 465),
          auth: user ? { user, pass } : undefined,
          // Avoid unusable IPv6 routes while retaining the hostname for SNI.
          getSocket: getIpv4Socket,

          // Fail fast instead of hanging. Nodemailer defaults to the OS TCP
          // timeout — minutes — and many PaaS hosts (Render included) block
          // outbound SMTP on 25/465/587, so the connection goes nowhere. With
          // signup awaiting delivery inline, that turned a blocked port into an
          // HTTP request that never returned: the client eventually gave up
          // while the account had already been written.
          //
          // 4s, not 10s: sendEmail() tries the primary transporter and THEN the
          // fallback, so the caller's worst case is roughly double this. The
          // website proxy aborts a GET after 10s (AbortSignal.timeout in
          // app/api/v1/[...path]/route.ts) and returns BACKEND_UNAVAILABLE, and
          // the Google OAuth callback is a GET that sends mail — so both
          // attempts must fit inside that budget or sign-in 504s instead of
          // merely losing its email. A healthy handshake is well under 1s.
          connectionTimeout: 4_000,
          greetingTimeout: 4_000,
          socketTimeout: 8_000,
        };
      }
      return null;
    };

    // Primary transporter setup
    const primaryConfig = createTransportConfig(
      this.config.SMTP_URL,
      this.config.SMTP_HOST,
      this.config.SMTP_PORT,
      this.config.SMTP_USER,
      this.config.SMTP_PASS,
      this.config.SMTP_SECURE
    );

    if (primaryConfig) {
      this.primaryTransporter = nodemailer.createTransport(primaryConfig as any);
    }

    // Fallback transporter setup
    const fallbackConfig = createTransportConfig(
      this.config.SMTP_FALLBACK_URL,
      this.config.SMTP_FALLBACK_HOST,
      this.config.SMTP_FALLBACK_PORT,
      this.config.SMTP_FALLBACK_USER,
      this.config.SMTP_FALLBACK_PASS,
      this.config.SMTP_FALLBACK_SECURE
    );

    if (fallbackConfig) {
      this.fallbackTransporter = nodemailer.createTransport(fallbackConfig as any);
    }
  }

  /**
   * Deliver over HTTPS instead of SMTP.
   *
   * The payload is a SUPERSET on purpose: `to`/`subject`/`html`/`text` let the
   * relay act as a dumb sender for any message we compose (including the
   * password-reset LINK, which has no code in it), while `email` and `otp`
   * mirror the older `{ email, otp }` contract so a script written against that
   * still delivers verification codes without being touched.
   *
   * Templates stay here rather than in PHP. Two copies of every email on two
   * servers in two languages would drift, and this service already builds both.
   */
  private async sendViaRelay(options: EmailOptions, from: string): Promise<boolean> {
    const url = this.config.PHP_MAILER_URL;
    if (!url) return false;

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.config.PHP_MAILER_API_KEY ? { 'X-API-Key': this.config.PHP_MAILER_API_KEY } : {}),
        },
        body: JSON.stringify({
          to: options.to,
          email: options.to,
          from,
          subject: options.subject,
          html: options.html,
          text: options.text,
          ...(options.otp ? { otp: options.otp } : {}),
        }),
        signal: AbortSignal.timeout(15_000),
      });

      if (!res.ok) {
        // The relay's body can echo configuration, so it is logged here and
        // never propagated to the caller.
        const detail = (await res.text().catch(() => '')).slice(0, 300);
        console.error(`❌ Mail relay responded ${res.status}: ${detail}`);
        return false;
      }
      return true;
    } catch (err) {
      console.error('❌ Mail relay unreachable:', err instanceof Error ? err.message : String(err));
      return false;
    }
  }

  public async sendEmail(options: EmailOptions): Promise<{ success: boolean; provider: 'relay' | 'primary' | 'fallback' | 'dev_log' }> {
    const primaryFrom = this.config.SMTP_FROM || this.config.SMTP_USER || 'noreply@gateways2026.com';
    const fallbackFrom = this.config.SMTP_FALLBACK_FROM || this.config.SMTP_FALLBACK_USER || primaryFrom;

    // 0. HTTP relay first when configured — on a host that blocks SMTP the
    //    transporters below can only ever time out.
    if (this.config.PHP_MAILER_URL) {
      if (await this.sendViaRelay(options, primaryFrom)) {
        return { success: true, provider: 'relay' };
      }
      console.warn('⚠️ Mail relay failed. Falling through to SMTP...');
    }

    // 1. Try Primary SMTP
    if (this.primaryTransporter) {
      try {
        await this.primaryTransporter.sendMail({
          from: primaryFrom,
          to: options.to,
          subject: options.subject,
          html: options.html,
          text: options.text,
        });
        return { success: true, provider: 'primary' };
      } catch (primaryErr) {
        console.warn('⚠️ Primary SMTP failed or rate-limited. Retrying with Fallback SMTP...', primaryErr);
      }
    }

    // 2. Try Fallback SMTP
    if (this.fallbackTransporter) {
      try {
        await this.fallbackTransporter.sendMail({
          from: fallbackFrom,
          to: options.to,
          subject: options.subject,
          html: options.html,
          text: options.text,
        });
        return { success: true, provider: 'fallback' };
      } catch (fallbackErr) {
        console.error('❌ Fallback SMTP also failed:', fallbackErr);
        throw fallbackErr;
      }
    }

    // 3. If no SMTP configured, log in development
    if (this.config.NODE_ENV === 'development' || this.config.NODE_ENV === 'test') {
      console.log(`[DEV EMAIL LOG] To: ${options.to} | Subject: ${options.subject}`);
      console.log(`[DEV EMAIL HTML] ${options.html}`);
      return { success: true, provider: 'dev_log' };
    }

    throw new Error('No SMTP transporter configured or all SMTP services failed.');
  }

  public async sendVerificationEmail(options: EmailVerificationOptions): Promise<{ success: boolean; provider: string }> {
    // Verification is a 6-digit OTP submitted via POST /api/v1/auth/verify-email —
    // there is no GET link the user can click. This previously defaulted to a
    // fabricated `?token=` URL against that POST-only route, so the "Verify Email"
    // button 404'd for every user who clicked it.
    //
    // A button is rendered only when a caller supplies a real FRONTEND url (which
    // is the frontend's own verification page, not an API endpoint). Otherwise the
    // email leads with the code, which is the thing that actually works.
    const verifyUrl = options.verificationUrl;

    const ctaBlock = verifyUrl
      ? `
        <p>Thank you for registering! Use the button below, or enter the code manually.</p>
        <div style="margin: 24px 0; text-align: center;">
          <a href="${verifyUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Verify Email</a>
        </div>
        <p style="color: #666; font-size: 14px;">Or enter this verification code:</p>`
      : `
        <p>Thank you for registering! Enter this verification code to confirm your email address:</p>`;

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #4f46e5;">Verify Your Email - PARALLAX Gateways 2026</h2>${ctaBlock}
        <code style="background-color: #f3f4f6; padding: 8px 12px; display: inline-block; border-radius: 4px; font-family: monospace; font-size: 20px; letter-spacing: 3px;">${options.verificationToken}</code>
        <p style="color: #666; font-size: 14px;">This code expires in 15 minutes.</p>
        <hr style="margin-top: 30px; border: none; border-top: 1px solid #e0e0e0;" />
        <p style="color: #999; font-size: 12px;">If you did not request this, please ignore this email.</p>
      </div>
    `;

    const text = verifyUrl
      ? `Verify your email for Gateways 2026 at ${verifyUrl} — or enter this code: ${options.verificationToken} (expires in 15 minutes).`
      : `Your Gateways 2026 verification code is ${options.verificationToken} (expires in 15 minutes).`;

    return this.sendEmail({
      to: options.to,
      subject: 'Verify your email for Gateways 2026',
      html,
      text,
      // Mirrors the older { email, otp } relay contract.
      otp: options.verificationToken,
    });
  }

  public async sendPasswordResetEmail(
    options: PasswordResetEmailOptions,
  ): Promise<{ success: boolean; provider: string }> {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #4f46e5;">Reset your Gateways 2026 password</h2>
        <p>We received a request to reset the password for your account.</p>
        <div style="margin: 24px 0; text-align: center;">
          <a href="${options.resetUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
        </div>
        <p style="color: #666; font-size: 14px;">This link expires in ${options.expiryMinutes} minutes and can be used only once.</p>
        <p style="color: #999; font-size: 12px;">If you did not request this, you can safely ignore this email.</p>
      </div>
    `;
    const text = `Reset your Gateways 2026 password: ${options.resetUrl}\n\nThis link expires in ${options.expiryMinutes} minutes and can be used only once. If you did not request this, ignore this email.`;

    return this.sendEmail({
      to: options.to,
      subject: 'Reset your Gateways 2026 password',
      html,
      text,
    });
  }
}

export const emailService = new EmailService();
