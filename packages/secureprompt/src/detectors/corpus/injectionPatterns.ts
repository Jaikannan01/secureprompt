/**
 * Corpus of injection pattern detection rules
 * 
 * This file contains regex patterns and thresholds for detecting obfuscated
 * injection attempts (Base64, URL encoding, hex, ROT13, Unicode escapes, etc.)
 * Edit this file to modify detection thresholds and patterns.
 */

/**
 * Base64 encoded injection detection
 * Pattern to match Base64 strings (50+ characters with optional padding)
 */
export const BASE64_PATTERN = /\b[A-Za-z0-9+/]{50,}={0,2}\b/g;

/**
 * URL encoding detection
 * Pattern to match URL-encoded strings (%XX format, at least 3 encoded characters)
 */
export const URL_ENCODED_PATTERN = /%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){2,}/g;

/**
 * Hex encoding detection
 * Pattern to match hex-encoded strings (even number of hex digits, at least 6 characters)
 */
export const HEX_ENCODED_PATTERN = /\b[0-9A-Fa-f]{6,}\b/g;

/**
 * ROT13 detection
 * Pattern to match potential ROT13-encoded text (alphabetic characters only, at least 10 chars)
 */
export const ROT13_PATTERN = /\b[A-Za-z]{10,}\b/g;

/**
 * Unicode escape detection
 * Pattern to match Unicode escapes in JSON/strings (\uXXXX format)
 */
export const UNICODE_ESCAPE_PATTERN = /\\u[0-9A-Fa-f]{4}(?:\\u[0-9A-Fa-f]{4}){2,}/g;

/**
 * Unicode obfuscation detection
 * Pattern to match suspicious Unicode characters that might be used for obfuscation
 * Includes:
 *   \u200B-\u200F  - zero-width space + bidi marks
 *   \u202A-\u202E  - bidi embedding/override
 *   \u2060-\u206F  - word joiner + invisibles
 *   \uFE00-\uFE0F  - variation selectors
 *   \uFEFF         - BOM
 *   \u00AD         - soft hyphen
 */
export const SUSPICIOUS_UNICODE_PATTERN = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF\u00AD]/g;

/**
 * Combining marks detection
 * Pattern to match combining diacritical marks that might be used for obfuscation
 */
export const COMBINING_MARKS_REGEX = /[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF]/g;

/**
 * Threshold for Unicode obfuscation detection
 * If more than this many suspicious Unicode characters are found, flag the input
 */
export const UNICODE_OBFUSCATION_THRESHOLD = 5;

/**
 * Minimum length for decoded content to check for injection patterns
 * Prevents false positives from very short encoded strings
 */
export const MIN_DECODED_LENGTH = 5;

/**
 * Alias for backward compatibility
 */
export const UNICODE_SUSPICIOUS_REGEX = SUSPICIOUS_UNICODE_PATTERN;

