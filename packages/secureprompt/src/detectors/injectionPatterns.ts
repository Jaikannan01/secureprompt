import { Detector, DetectionResult } from './baseDetector';
import {
  BASE64_PATTERN,
  URL_ENCODED_PATTERN,
  HEX_ENCODED_PATTERN,
  ROT13_PATTERN,
  UNICODE_ESCAPE_PATTERN,
  SUSPICIOUS_UNICODE_PATTERN,
  COMBINING_MARKS_REGEX,
  UNICODE_OBFUSCATION_THRESHOLD,
  MIN_DECODED_LENGTH,
} from './corpus/injectionPatterns';
import { BASE64_DECODED_KEYWORDS } from './corpus/injectionPhrases';
import {
  decodeURL,
  decodeHex,
  decodeROT13,
  decodeUnicodeEscapes,
  looksLikeROT13,
} from './utils/decoding';
import { findLookalikeKeywords } from './utils/lookalikes';

/**
 * Detector for pattern-based obfuscation attempts
 * Detects Base64, URL encoding, hex, ROT13, Unicode escapes, and Unicode obfuscation
 */
class InjectionPatternDetector implements Detector {
  name = 'injection-patterns';
  enabled = true;

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];

    // Base64 encoded attempts
    results.push(...this.detectBase64Encoded(text));

    // URL encoded attempts
    results.push(...this.detectURLEncoded(text));

    // Hex encoded attempts
    results.push(...this.detectHexEncoded(text));

    // ROT13 encoded attempts
    results.push(...this.detectROT13Encoded(text));

    // Unicode escape attempts
    results.push(...this.detectUnicodeEscapes(text));

    // Lookalike character detection
    results.push(...this.detectLookalikes(text));

    // Combining marks detection
    results.push(...this.detectCombiningMarks(text));

    // Unicode obfuscation
    results.push(...this.detectUnicodeObfuscation(text));

    return results;
  }

  private detectBase64Encoded(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match;
    BASE64_PATTERN.lastIndex = 0;

    while ((match = BASE64_PATTERN.exec(text)) !== null) {
      // Try to decode and check if it contains suspicious content
      try {
        // Use Buffer in Node.js, atob in browser
        let decoded: string;
        if (typeof Buffer !== 'undefined') {
          decoded = Buffer.from(match[0], 'base64').toString('utf-8');
        } else {
          decoded = atob(match[0]);
        }
        const lowerDecoded = decoded.toLowerCase();
        // Check if decoded content contains injection patterns
        const containsSuspiciousKeyword = BASE64_DECODED_KEYWORDS.some(keyword =>
          lowerDecoded.includes(keyword)
        );
        if (containsSuspiciousKeyword) {
          results.push({
            type: 'base64-encoded-injection',
            severity: 'high',
            matched: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            context: 'Base64 encoded content with potential injection patterns',
          });
        }
      } catch {
        // Not valid base64, skip
      }
    }

    return results;
  }

  private detectURLEncoded(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match: RegExpExecArray | null;
    URL_ENCODED_PATTERN.lastIndex = 0;

    while ((match = URL_ENCODED_PATTERN.exec(text)) !== null) {
      const decoded = decodeURL(match[0]);
      if (decoded && decoded.length >= MIN_DECODED_LENGTH) {
        const lowerDecoded = decoded.toLowerCase();
        const containsSuspiciousKeyword = BASE64_DECODED_KEYWORDS.some(keyword =>
          lowerDecoded.includes(keyword)
        );
        if (containsSuspiciousKeyword) {
          results.push({
            type: 'url-encoded-injection',
            severity: 'high',
            matched: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            context: 'URL-encoded content with potential injection patterns',
          });
        }
      }
    }

    return results;
  }

  private detectHexEncoded(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match: RegExpExecArray | null;
    HEX_ENCODED_PATTERN.lastIndex = 0;

    while ((match = HEX_ENCODED_PATTERN.exec(text)) !== null) {
      // Skip if it looks like a regular hex number (too short or common patterns)
      if (match[0].length < 10) {
        continue;
      }
      
      const decoded = decodeHex(match[0]);
      if (decoded && decoded.length >= MIN_DECODED_LENGTH) {
        const lowerDecoded = decoded.toLowerCase();
        const containsSuspiciousKeyword = BASE64_DECODED_KEYWORDS.some(keyword =>
          lowerDecoded.includes(keyword)
        );
        if (containsSuspiciousKeyword) {
          results.push({
            type: 'hex-encoded-injection',
            severity: 'high',
            matched: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            context: 'Hex-encoded content with potential injection patterns',
          });
        }
      }
    }

    return results;
  }

  private detectROT13Encoded(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match: RegExpExecArray | null;
    ROT13_PATTERN.lastIndex = 0;

    while ((match = ROT13_PATTERN.exec(text)) !== null) {
      // Only check if it looks like it could be ROT13
      if (!looksLikeROT13(match[0])) {
        continue;
      }

      const decoded = decodeROT13(match[0]);
      if (decoded.length >= MIN_DECODED_LENGTH) {
        const lowerDecoded = decoded.toLowerCase();
        const containsSuspiciousKeyword = BASE64_DECODED_KEYWORDS.some(keyword =>
          lowerDecoded.includes(keyword)
        );
        if (containsSuspiciousKeyword) {
          results.push({
            type: 'rot13-encoded-injection',
            severity: 'high',
            matched: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            context: 'ROT13-encoded content with potential injection patterns',
          });
        }
      }
    }

    return results;
  }

  private detectUnicodeEscapes(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match: RegExpExecArray | null;
    UNICODE_ESCAPE_PATTERN.lastIndex = 0;

    while ((match = UNICODE_ESCAPE_PATTERN.exec(text)) !== null) {
      const decoded = decodeUnicodeEscapes(match[0]);
      if (decoded && decoded.length >= MIN_DECODED_LENGTH) {
        const lowerDecoded = decoded.toLowerCase();
        const containsSuspiciousKeyword = BASE64_DECODED_KEYWORDS.some(keyword =>
          lowerDecoded.includes(keyword)
        );
        if (containsSuspiciousKeyword) {
          results.push({
            type: 'unicode-escape-injection',
            severity: 'high',
            matched: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            context: 'Unicode escape-encoded content with potential injection patterns',
          });
        }
      }
    }

    return results;
  }

  private detectLookalikes(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    const lookalikeMatches = findLookalikeKeywords(text);

    for (const match of lookalikeMatches) {
      results.push({
        type: 'lookalike-injection',
        severity: 'critical',
        matched: match.matched,
        startIndex: match.startIndex,
        endIndex: match.endIndex,
        context: `Lookalike character detected in critical keyword: "${match.keyword}"`,
      });
    }

    return results;
  }

  private detectCombiningMarks(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match: RegExpExecArray | null;
    let matchCount = 0;
    const markPositions: number[] = [];
    COMBINING_MARKS_REGEX.lastIndex = 0;

    while ((match = COMBINING_MARKS_REGEX.exec(text)) !== null) {
      matchCount++;
      markPositions.push(match.index);
    }

    // If there are many combining marks, flag it
    if (matchCount > UNICODE_OBFUSCATION_THRESHOLD) {
      results.push({
        type: 'combining-marks-obfuscation',
        severity: 'medium',
        matched: text,
        startIndex: 0,
        endIndex: text.length,
        context: `Excessive combining marks detected (${matchCount} marks)`,
      });
    } else if (matchCount > 0) {
      // Check if combining marks are near critical keywords
      const normalizedText = text.toLowerCase();
      const criticalKeywords = ['system', 'developer', 'ignore', 'override', 'instructions', 'bypass', 'jailbreak'];
      
      for (const keyword of criticalKeywords) {
        const keywordIndex = normalizedText.indexOf(keyword);
        if (keywordIndex !== -1) {
          // Check if any combining marks are near this keyword
          const keywordEnd = keywordIndex + keyword.length;
          const nearbyMarks = markPositions.filter(pos => 
            pos >= keywordIndex - 5 && pos <= keywordEnd + 5
          );
          
          if (nearbyMarks.length > 0) {
            results.push({
              type: 'combining-marks-injection',
              severity: 'high',
              matched: text.substring(Math.max(0, keywordIndex - 5), Math.min(text.length, keywordEnd + 5)),
              startIndex: Math.max(0, keywordIndex - 5),
              endIndex: Math.min(text.length, keywordEnd + 5),
              context: `Combining marks detected near critical keyword: "${keyword}"`,
            });
            break; // Only report once per text
          }
        }
      }
    }

    return results;
  }

  private detectUnicodeObfuscation(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    let match;
    let matchCount = 0;
    SUSPICIOUS_UNICODE_PATTERN.lastIndex = 0;

    while ((match = SUSPICIOUS_UNICODE_PATTERN.exec(text)) !== null) {
      matchCount++;
    }

    // If there are many suspicious Unicode characters, flag it
    if (matchCount > UNICODE_OBFUSCATION_THRESHOLD) {
      results.push({
        type: 'unicode-obfuscation',
        severity: 'medium',
        matched: text,
        startIndex: 0,
        endIndex: text.length,
        context: 'Potential Unicode obfuscation detected',
      });
    }

    return results;
  }
}

export const injectionPatternDetector = new InjectionPatternDetector();
