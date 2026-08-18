export type DataErrorCode =
  | 'NOT_AUTHENTICATED'
  | 'INVALID_CREDENTIALS'
  | 'EMAIL_TAKEN'
  | 'PLAYER_NAME_TAKEN'
  | 'NOT_FOUND'
  | 'ALREADY_REGISTERED'
  | 'EVENT_FULL'
  | 'REGISTRATION_CLOSED'
  | 'TEAM_FULL'
  | 'TEAM_LOCKED'
  | 'INVALID_JOIN_CODE'
  | 'STORAGE_UNAVAILABLE'
  | 'VALIDATION_FAILED'
  | 'RECEIPT_ALREADY_SUBMITTED'
  | 'PAYMENT_NOT_VERIFIED'
  | 'FORBIDDEN'
  | 'MUST_CHANGE_PASSWORD'
  | 'EMAIL_NOT_VERIFIED'
  | 'OAUTH_ACCOUNT'
  | 'INTERNAL_ERROR';

export interface DataErrorDetails {
  code: DataErrorCode;
  message: string;
  statusCode: number;
  retryable: boolean;
  correlationId?: string;
  details?: Record<string, unknown>;
}

export class DataError extends Error {
  public readonly code: DataErrorCode;
  public readonly statusCode: number;
  public readonly retryable: boolean;
  public readonly correlationId?: string;
  public readonly details?: Record<string, unknown>;

  constructor(params: DataErrorDetails) {
    super(params.message);
    this.name = 'DataError';
    this.code = params.code;
    this.statusCode = params.statusCode;
    this.retryable = params.retryable;
    this.correlationId = params.correlationId;
    this.details = params.details;
    Object.setPrototypeOf(this, DataError.prototype);
  }
}

export const ERROR_MAPPINGS: Record<DataErrorCode, { statusCode: number; retryable: boolean }> = {
  VALIDATION_FAILED: { statusCode: 400, retryable: false },
  NOT_AUTHENTICATED: { statusCode: 401, retryable: false },
  INVALID_CREDENTIALS: { statusCode: 401, retryable: false },
  FORBIDDEN: { statusCode: 403, retryable: false },
  MUST_CHANGE_PASSWORD: { statusCode: 403, retryable: false },
  NOT_FOUND: { statusCode: 404, retryable: false },
  EMAIL_TAKEN: { statusCode: 409, retryable: false },
  PLAYER_NAME_TAKEN: { statusCode: 409, retryable: false },
  ALREADY_REGISTERED: { statusCode: 409, retryable: false },
  TEAM_FULL: { statusCode: 409, retryable: false },
  TEAM_LOCKED: { statusCode: 409, retryable: false },
  INVALID_JOIN_CODE: { statusCode: 409, retryable: false },
  RECEIPT_ALREADY_SUBMITTED: { statusCode: 409, retryable: false },
  // 409 rather than 403: FORBIDDEN/MUST_CHANGE_PASSWORD mean "you may not",
  // whereas both of these mean "the account is in a state this request can't
  // use" and are recoverable by the caller taking a different route.
  EMAIL_NOT_VERIFIED: { statusCode: 409, retryable: false },
  OAUTH_ACCOUNT: { statusCode: 409, retryable: false },
  REGISTRATION_CLOSED: { statusCode: 422, retryable: false },
  EVENT_FULL: { statusCode: 422, retryable: false },
  PAYMENT_NOT_VERIFIED: { statusCode: 422, retryable: false },
  STORAGE_UNAVAILABLE: { statusCode: 503, retryable: true },
  INTERNAL_ERROR: { statusCode: 500, retryable: false },
};

export function createDataError(
  code: DataErrorCode,
  customMessage?: string,
  correlationId?: string,
  details?: Record<string, unknown>
): DataError {
  const meta = ERROR_MAPPINGS[code] || { statusCode: 500, retryable: false };
  const defaultMessages: Record<DataErrorCode, string> = {
    NOT_AUTHENTICATED: 'Authentication required. Please sign in.',
    INVALID_CREDENTIALS: 'Invalid email or password.',
    EMAIL_TAKEN: 'An account with this email address already exists.',
    PLAYER_NAME_TAKEN: 'Player name is already taken.',
    NOT_FOUND: 'The requested resource was not found.',
    ALREADY_REGISTERED: 'You are already registered for this event.',
    EVENT_FULL: 'Event capacity reached.',
    REGISTRATION_CLOSED: 'Registration for this event is currently closed.',
    TEAM_FULL: 'Team has reached its maximum member limit.',
    TEAM_LOCKED: 'This team is locked and cannot be changed.',
    INVALID_JOIN_CODE: 'Invalid or expired team join code.',
    STORAGE_UNAVAILABLE: 'Storage service is temporarily unavailable. Please try again.',
    VALIDATION_FAILED: 'Validation failed for request parameters.',
    RECEIPT_ALREADY_SUBMITTED: 'A payment receipt has already been submitted for your account.',
    PAYMENT_NOT_VERIFIED: 'Action requires a verified payment.',
    FORBIDDEN: 'You do not have permission to perform this action.',
    MUST_CHANGE_PASSWORD: 'You must change your temporary password before continuing.',
    EMAIL_NOT_VERIFIED: 'Please verify your email address to continue. We sent you a new code.',
    OAUTH_ACCOUNT: 'This account signs in with Google. Use the Google button instead.',
    INTERNAL_ERROR: 'An internal server error occurred. Please try again later.',
  };

  return new DataError({
    code,
    message: customMessage || defaultMessages[code],
    statusCode: meta.statusCode,
    retryable: meta.retryable,
    correlationId,
    details,
  });
}
