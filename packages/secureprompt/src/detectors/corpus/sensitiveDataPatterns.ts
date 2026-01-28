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
export const CREDIT_CARD_PATTERN = /\b(?:\d[ -]?){13,19}\b/g;

/**
 * Social Security Number detection pattern
 * Matches XXX-XX-XXXX or XXXXXXXXX format
 */
export const SSN_PATTERN = /\b\d{3}-?\d{2}-?\d{4}\b/g;

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
export const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;

/**
 * Phone number detection pattern
 * US phone numbers: (XXX) XXX-XXXX, XXX-XXX-XXXX, XXX.XXX.XXXX, etc.
 * Supports optional country code (+1)
 */
export const PHONE_PATTERN = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;

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
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g,
    type: 'openai-api-key',
    severity: 'high',
  },
  // Anthropic (Claude) API keys
  {
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    type: 'anthropic-api-key',
    severity: 'high',
  },
  // Google API keys
  {
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    type: 'google-api-key',
    severity: 'high',
  },
  // Google OAuth client secrets
  {
    pattern: /\bGOCSPX-[0-9A-Za-z_-]{20,}\b/g,
    type: 'google-oauth-client-secret',
    severity: 'high',
  },
  // AWS Access Key ID
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    type: 'aws-access-key',
    severity: 'high',
  },
  // AWS Session token (shortened pattern; very long base64)
  {
    pattern: /\bAQoDYXdzE[A-Za-z0-9+/]{20,}={0,2}\b/g,
    type: 'aws-session-token',
    severity: 'high',
  },
  // GitHub token
  {
    pattern: /\bghp_[a-zA-Z0-9]{36}\b/g,
    type: 'github-token',
    severity: 'high',
  },
  {
    pattern: /\bgho_[a-zA-Z0-9]{36}\b/g,
    type: 'github-oauth-token',
    severity: 'high',
  },
  {
    pattern: /\bghs_[a-zA-Z0-9]{36}\b/g,
    type: 'github-app-token',
    severity: 'high',
  },
  {
    pattern: /\bghu_[a-zA-Z0-9]{36}\b/g,
    type: 'github-user-token',
    severity: 'high',
  },
  // Stripe secret keys
  {
    pattern: /\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b/g,
    type: 'stripe-secret-key',
    severity: 'high',
  },
  // Slack tokens
  {
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g,
    type: 'slack-token',
    severity: 'high',
  },
  // Twilio API keys (SK...); Account SIDs (AC...) are identifiers but still sensitive
  {
    pattern: /\bSK[0-9a-fA-F]{32}\b/g,
    type: 'twilio-api-key',
    severity: 'high',
  },
  {
    pattern: /\bAC[0-9a-fA-F]{32}\b/g,
    type: 'twilio-account-sid',
    severity: 'medium',
  },
  // SendGrid API keys
  {
    pattern: /\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    type: 'sendgrid-api-key',
    severity: 'high',
  },
  // Mailgun API keys
  {
    pattern: /\bkey-[0-9a-f]{32}\b/gi,
    type: 'mailgun-api-key',
    severity: 'high',
  },
  // Firebase server keys (legacy FCM server keys start with AAAA)
  {
    pattern: /\bAAAA[A-Za-z0-9_-]{20,}\b/g,
    type: 'firebase-server-key',
    severity: 'high',
  },
  // SHA-256 hex digests
  {
    pattern: /\b[a-f0-9]{64}\b/gi,
    type: 'sha256-hash',
    severity: 'medium',
  },
  // Generic API key patterns (long alphanumeric strings)
  {
    pattern: /\b[a-zA-Z0-9]{32,}\b/g,
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
export const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
