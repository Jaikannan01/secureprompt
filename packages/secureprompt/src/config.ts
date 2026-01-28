import { Detector } from './detectors/baseDetector';

/**
 * Action to take when a violation is detected
 */
export type ViolationAction = 'block' | 'redact' | 'warn';

/**
 * Configuration for the sanitizer
 */
export interface SanitizerConfig {
  /** Action to take when violations are detected */
  action?: ViolationAction;
  /** Custom detectors to add */
  customDetectors?: Detector[];
  /** Detectors to disable by name */
  disabledDetectors?: string[];
  /** Whether to return detailed detection results */
  detailedResults?: boolean;
  /** Custom redaction placeholder (default: '[REDACTED]') */
  redactionPlaceholder?: string;
}

/**
 * Default configuration
 */
export const DEFAULT_CONFIG: Required<Omit<SanitizerConfig, 'customDetectors' | 'disabledDetectors'>> = {
  action: 'block',
  detailedResults: false,
  redactionPlaceholder: '[REDACTED]',
};

/**
 * Get configuration with defaults applied
 */
export function getConfig(config?: SanitizerConfig): Required<Omit<SanitizerConfig, 'customDetectors' | 'disabledDetectors'>> & Pick<SanitizerConfig, 'customDetectors' | 'disabledDetectors'> {
  return {
    ...DEFAULT_CONFIG,
    ...config,
  };
}
