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
  // AWS Access Key ID
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    type: 'aws-access-key',
    severity: 'high',
  },
  // GitHub token
  {
    pattern: /\bghp_[a-zA-Z0-9]{36}\b/g,
    type: 'github-token',
    severity: 'high',
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
  /^[0-9a-f]{32,}$/i, // Hexadecimal hashes (MD5, SHA256, etc.)
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUIDs
];

/**
 * IPv4 address detection pattern
 * Matches valid IPv4 addresses (0.0.0.0 to 255.255.255.255)
 */
export const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

