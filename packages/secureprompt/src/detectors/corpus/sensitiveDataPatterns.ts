/**
 * Corpus of sensitive data detection patterns
 * 
 * This file contains all the regex patterns and validation rules used to detect
 * sensitive information like credit cards, SSNs, emails, etc.
 * Edit this file to add, remove, or modify detection patterns.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Credit card detection pattern
 * Matches 13-19 digits with optional spaces or dashes
 */
export const CREDIT_CARD_PATTERN = /(?:\d[ -]?){13,19}/g;

/**
 * Social Security Number detection pattern
 * Matches XXX-XX-XXXX or XXXXXXXXX format
 */
export const SSN_PATTERN = /\d{3}-?\d{2}-?\d{4}/g;

/**
 * Invalid SSN prefixes that should be excluded
 * SSNs cannot start with 000, 666, or 900-999
 */
export const INVALID_SSN_PREFIXES = {
  ZERO: 0,
  SIX_SIX_SIX: 666,
  MIN_INVALID_RANGE: 900,
};

/**
 * Email address detection pattern
 * Standard email regex pattern
 */
export const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/g;

/**
 * Phone number detection pattern
 * US phone numbers: (XXX) XXX-XXXX, XXX-XXX-XXXX, XXX.XXX.XXXX, etc.
 * Supports optional country code (+1)
 */
export const PHONE_PATTERN = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

/**
 * API key detection patterns
 * Each pattern includes the regex, detection type, and severity
 */
export interface APIKeyPattern {
  pattern: RegExp;
  type: string;
  severity: Severity;
}

export const API_KEY_PATTERNS: APIKeyPattern[] = [
  // OpenAI API keys (legacy + project keys)
  {
    pattern: /sk-(?:proj-)?[A-Za-z0-9]{20,}/g,
    type: 'openai-api-key',
    severity: 'high',
  },
  // Anthropic (Claude) API keys
  {
    pattern: /sk-ant-[A-Za-z0-9_-]{20,}/g,
    type: 'anthropic-api-key',
    severity: 'high',
  },
  // Google API keys
  {
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    type: 'google-api-key',
    severity: 'high',
  },
  // Google OAuth client secrets
  {
    pattern: /GOCSPX-[0-9A-Za-z_-]{20,}/g,
    type: 'google-oauth-client-secret',
    severity: 'high',
  },
  // AWS Access Key ID
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    type: 'aws-access-key',
    severity: 'high',
  },
  // AWS Session token (shortened pattern; very long base64)
  {
    pattern: /AQoDYXdzE[A-Za-z0-9+/]{20,}={0,2}/g,
    type: 'aws-session-token',
    severity: 'high',
  },
  // GitHub token
  {
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    type: 'github-token',
    severity: 'high',
  },
  {
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    type: 'github-oauth-token',
    severity: 'high',
  },
  {
    pattern: /ghs_[a-zA-Z0-9]{36}/g,
    type: 'github-app-token',
    severity: 'high',
  },
  {
    pattern: /ghu_[a-zA-Z0-9]{36}/g,
    type: 'github-user-token',
    severity: 'high',
  },
  // Stripe secret keys
  {
    pattern: /sk_(?:live|test)_[0-9a-zA-Z]{16,}/g,
    type: 'stripe-secret-key',
    severity: 'high',
  },
  // Slack tokens
  {
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,48}/g,
    type: 'slack-token',
    severity: 'high',
  },
  // Twilio API keys (SK...); Account SIDs (AC...) are identifiers but still sensitive
  {
    pattern: /SK[0-9a-fA-F]{32}/g,
    type: 'twilio-api-key',
    severity: 'high',
  },
  {
    pattern: /AC[0-9a-fA-F]{32}/g,
    type: 'twilio-account-sid',
    severity: 'medium',
  },
  // SendGrid API keys
  {
    pattern: /SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    type: 'sendgrid-api-key',
    severity: 'high',
  },
  // Mailgun API keys
  {
    pattern: /key-[0-9a-f]{32}/gi,
    type: 'mailgun-api-key',
    severity: 'high',
  },
  // Firebase server keys (legacy FCM server keys start with AAAA)
  {
    pattern: /AAAA[A-Za-z0-9_-]{20,}/g,
    type: 'firebase-server-key',
    severity: 'high',
  },
  // SHA-256 hex digests
  {
    pattern: /[a-f0-9]{64}/gi,
    type: 'sha256-hash',
    severity: 'medium',
  },
  // Generic API key patterns (long alphanumeric strings)
  {
    pattern: /[a-zA-Z0-9]{32,}/g,
    type: 'api-key',
    severity: 'medium',
  },
];

/**
 * Patterns to exclude from API key detection (false positives)
 * These patterns match hashes and UUIDs that shouldn't be flagged as API keys
 */
export const API_KEY_EXCLUSION_PATTERNS = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUIDs
];

/**
 * IPv4 address detection pattern
 * Matches valid IPv4 addresses (0.0.0.0 to 255.255.255.255)
 */
export const IPV4_PATTERN = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;
