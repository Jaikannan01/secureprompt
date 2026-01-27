import { Detector, DetectionResult } from './baseDetector';
import { luhnCheck } from '../utils/validation';
import {
  CREDIT_CARD_PATTERN,
  SSN_PATTERN,
  INVALID_SSN_PREFIXES,
  EMAIL_PATTERN,
  PHONE_PATTERN,
  API_KEY_PATTERNS,
  API_KEY_EXCLUSION_PATTERNS,
  IPV4_PATTERN,
} from './corpus/sensitiveDataPatterns';

/**
 * Detector for sensitive data like credit cards, SSNs, emails, etc.
 */
class SensitiveDataDetector implements Detector {
  name = 'sensitive-data';
  enabled = true;

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];

    // Credit card detection
    results.push(...this.detectCreditCards(text));

    // SSN detection
    results.push(...this.detectSSNs(text));

    // Email detection
    results.push(...this.detectEmails(text));

    // Phone number detection
    results.push(...this.detectPhoneNumbers(text));

    // API key detection
    results.push(...this.detectAPIKeys(text));

    // IP address detection
    results.push(...this.detectIPAddresses(text));

    return results;
  }

  private detectCreditCards(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match;

    while ((match = CREDIT_CARD_PATTERN.exec(text)) !== null) {
      const cardNumber = match[0].replace(/[ -]/g, '');
      // Validate with Luhn algorithm
      if (luhnCheck(cardNumber)) {
        results.push({
          type: 'credit-card',
          severity: 'critical',
          matched: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          context: 'Valid credit card number detected',
        });
      }
    }

    return results;
  }

  private detectSSNs(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match;

    while ((match = SSN_PATTERN.exec(text)) !== null) {
      // Basic validation: first 3 digits shouldn't be 000, 666, or 900-999
      const ssn = match[0].replace(/-/g, '');
      const firstThree = parseInt(ssn.substring(0, 3), 10);
      if (
        firstThree !== INVALID_SSN_PREFIXES.ZERO &&
        firstThree !== INVALID_SSN_PREFIXES.SIX_SIX_SIX &&
        firstThree < INVALID_SSN_PREFIXES.MIN_INVALID_RANGE
      ) {
        results.push({
          type: 'ssn',
          severity: 'critical',
          matched: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          context: 'Potential Social Security Number detected',
        });
      }
    }

    return results;
  }

  private detectEmails(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match;

    while ((match = EMAIL_PATTERN.exec(text)) !== null) {
      results.push({
        type: 'email',
        severity: 'medium',
        matched: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        context: 'Email address detected',
      });
    }

    return results;
  }

  private detectPhoneNumbers(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match;

    while ((match = PHONE_PATTERN.exec(text)) !== null) {
      results.push({
        type: 'phone',
        severity: 'medium',
        matched: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        context: 'Phone number detected',
      });
    }

    return results;
  }

  private detectAPIKeys(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];

    for (const { pattern, type, severity } of API_KEY_PATTERNS) {
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        // Skip if it matches exclusion patterns (hashes, UUIDs, etc.)
        const isExcluded = API_KEY_EXCLUSION_PATTERNS.some(exclusionPattern =>
          exclusionPattern.test(match![0])
        );
        if (isExcluded) {
          continue;
        }
        results.push({
          type,
          severity,
          matched: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          context: `Potential ${type} detected`,
        });
      }
    }

    return results;
  }

  private detectIPAddresses(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match;

    while ((match = IPV4_PATTERN.exec(text)) !== null) {
      results.push({
        type: 'ip-address',
        severity: 'low',
        matched: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        context: 'IP address detected',
      });
    }

    return results;
  }
}

export const sensitiveDataDetector = new SensitiveDataDetector();

