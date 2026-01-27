import { Detector, DetectionResult } from './baseDetector';
import {
  PROMPT_INJECTION_PHRASES,
  JAILBREAK_PATTERNS,
  SYSTEM_PROMPT_EXTRACTION_PHRASES,
  TRAINING_DATA_EXTRACTION_PHRASES,
} from './corpus/injectionPhrases';

/**
 * Detector for phrase-based injection attempts
 * Detects prompt injection, jailbreak attempts, and system prompt extraction using phrase matching
 */
class InjectionPhrasesDetector implements Detector {
  name = 'injection-phrases';
  enabled = true;

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];

    // Prompt injection phrases
    results.push(...this.detectPromptInjection(text));

    // Jailbreak attempts
    results.push(...this.detectJailbreakAttempts(text));

    // System prompt extraction attempts
    results.push(...this.detectSystemPromptExtraction(text));

    // Training data extraction attempts
    results.push(...this.detectTrainingDataExtraction(text));

    return results;
  }

  private detectPromptInjection(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    const lowerText = text.toLowerCase();

    for (const { phrase, severity } of PROMPT_INJECTION_PHRASES) {
      const index = lowerText.indexOf(phrase);
      if (index !== -1) {
        results.push({
          type: 'prompt-injection',
          severity,
          matched: text.substring(index, index + phrase.length),
          startIndex: index,
          endIndex: index + phrase.length,
          context: `Prompt injection phrase detected: "${phrase}"`,
        });
      }
    }

    return results;
  }

  private detectJailbreakAttempts(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];

    for (const { pattern, severity } of JAILBREAK_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        const index = match.index!;
        results.push({
          type: 'jailbreak',
          severity,
          matched: match[0],
          startIndex: index,
          endIndex: index + match[0].length,
          context: 'Potential jailbreak attempt detected',
        });
      }
    }

    return results;
  }

  private detectSystemPromptExtraction(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    const lowerText = text.toLowerCase();

    for (const phrase of SYSTEM_PROMPT_EXTRACTION_PHRASES) {
      const index = lowerText.indexOf(phrase);
      if (index !== -1) {
        results.push({
          type: 'system-prompt-extraction',
          severity: 'high',
          matched: text.substring(index, index + phrase.length),
          startIndex: index,
          endIndex: index + phrase.length,
          context: 'Attempt to extract system prompt detected',
        });
      }
    }

    return results;
  }

  private detectTrainingDataExtraction(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    const lowerText = text.toLowerCase();

    for (const phrase of TRAINING_DATA_EXTRACTION_PHRASES) {
      const index = lowerText.indexOf(phrase);
      if (index !== -1) {
        results.push({
          type: 'training-data-extraction',
          severity: 'high',
          matched: text.substring(index, index + phrase.length),
          startIndex: index,
          endIndex: index + phrase.length,
          context: 'Attempt to extract training data detected',
        });
      }
    }

    return results;
  }
}

export const injectionPhrasesDetector = new InjectionPhrasesDetector();

