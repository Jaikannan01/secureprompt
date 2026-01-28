import { Detector, DetectionResult } from './detectors/baseDetector';
import { SanitizerConfig, getConfig, ViolationAction } from './config';
import { validateInput } from './utils/validation';
import { sensitiveDataDetector } from './detectors/sensitiveData';
import { injectionPhrasesDetector } from './detectors/injectionPhrases';
import { injectionPatternDetector } from './detectors/injectionPatterns';

/**
 * Result of sanitization
 */
export interface SanitizationResult {
  /** Whether the input passed sanitization */
  isValid: boolean;
  /** The sanitized output (may be redacted or blocked) */
  sanitized: string;
  /** Array of detected violations */
  violations: DetectionResult[];
  /** Whether the input was blocked */
  blocked: boolean;
}

/**
 * Sanitize a prompt input
 */
export function sanitizePrompt(
  input: string,
  config?: SanitizerConfig
): SanitizationResult {
  validateInput(input);

  const finalConfig = getConfig(config);
  const detectors: Detector[] = [
    sensitiveDataDetector,
    injectionPhrasesDetector,
    injectionPatternDetector,
    ...(finalConfig.customDetectors || []),
  ].filter((detector) => {
    // Filter out disabled detectors
    if (finalConfig.disabledDetectors?.includes(detector.name)) {
      return false;
    }
    return detector.enabled;
  });

  // Run all detectors
  const allViolations: DetectionResult[] = [];
  for (const detector of detectors) {
    const results = detector.detect(input);
    allViolations.push(...results);
  }

  // Merge overlapping violations into union ranges for redaction only
  const mergedViolations = mergeOverlappingViolations(allViolations);

  // Sort violations by severity (critical first)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allViolations.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Determine if we should block
  const shouldBlock = allViolations.some(
    (v) => v.severity === 'critical' || v.severity === 'high'
  ) && finalConfig.action === 'block';

  let sanitized = input;
  let isValid = allViolations.length === 0;

  // Apply action based on config
  if (shouldBlock) {
    sanitized = '';
    isValid = false;
  } else if (finalConfig.action === 'redact' && mergedViolations.length > 0) {
    // Redact violations (in reverse order to preserve indices)
    const violationsToRedact = [...mergedViolations].sort((a, b) => b.startIndex - a.startIndex);
    for (const violation of violationsToRedact) {
      sanitized =
        sanitized.slice(0, violation.startIndex) +
        finalConfig.redactionPlaceholder +
        sanitized.slice(violation.endIndex);
    }
  }

  return {
    isValid,
    sanitized,
    violations: finalConfig.detailedResults ? allViolations : [],
    blocked: shouldBlock,
  };
}

function mergeOverlappingViolations(results: DetectionResult[]): DetectionResult[] {
  if (results.length <= 1) return results;
  const sorted = results.slice().sort((a, b) => a.startIndex - b.startIndex);
  const merged: DetectionResult[] = [];

  for (const current of sorted) {
    const last = merged[merged.length - 1];
    if (!last) {
      merged.push({ ...current });
      continue;
    }

    if (current.startIndex <= last.endIndex) {
      // Union overlapping ranges; keep severity/type from the first seen range.
      last.endIndex = Math.max(last.endIndex, current.endIndex);
      if (last.matched.length < last.endIndex - last.startIndex) {
        last.matched = '';
        last.context = undefined;
      }
    } else {
      merged.push({ ...current });
    }
  }

  return merged;
}
