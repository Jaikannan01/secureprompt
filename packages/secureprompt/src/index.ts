/**
 * SecurePrompt - LLM Input Sanitization Library
 * 
 * A library for sanitizing LLM prompt inputs to prevent sensitive data leaks
 * and injection attacks.
 */

export { sanitizePrompt } from './sanitizer';
export type { SanitizationResult } from './sanitizer';

export type { SanitizerConfig, SanitizationMode, ViolationAction } from './config';

export type { Detector, DetectionResult } from './detectors/baseDetector';

// Re-export for convenience
export { DEFAULT_CONFIG } from './config';

