/**
 * Base interface for all detectors
 */
export interface DetectionResult {
  /** Type of detection (e.g., 'credit-card', 'injection', 'ssn') */
  type: string;
  /** Severity level of the detection */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** The matched text or pattern */
  matched: string;
  /** Start position of the match in the input */
  startIndex: number;
  /** End position of the match in the input */
  endIndex: number;
  /** Additional context about the detection */
  context?: string;
}

/**
 * Base detector interface that all detectors must implement
 */
export interface Detector {
  /** Unique name identifier for this detector */
  name: string;
  /** Detect issues in the given text */
  detect(text: string): DetectionResult[];
  /** Whether this detector is enabled */
  enabled: boolean;
}

