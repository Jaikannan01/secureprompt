import { Detector, DetectionResult } from './baseDetector';
import {
  PROMPT_INJECTION_PHRASES,
  JAILBREAK_PATTERNS,
  SYSTEM_PROMPT_EXTRACTION_PHRASES,
  TRAINING_DATA_EXTRACTION_PHRASES,
  SYNONYMS,
} from './corpus/injectionPhrases';
import { GENERATED_PHRASES } from './corpus/generated';

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

    // Ordered synonym sequence detection (e.g., ignore ... previous ... instructions)
    results.push(...this.detectOrderedSynonymSequences(text));

    return results;
  }

  private detectPromptInjection(text: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    const lowerText = text.toLowerCase();

    // Static curated phrases
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

    // Auto-generated permutations corpus (treated as high severity)
    for (const rawPhrase of GENERATED_PHRASES) {
      const phrase = rawPhrase.toLowerCase();
      const index = lowerText.indexOf(phrase);
      if (index !== -1) {
        results.push({
          type: 'prompt-injection',
          severity: 'high',
          matched: text.substring(index, index + phrase.length),
          startIndex: index,
          endIndex: index + phrase.length,
          context: 'Matched generated injection phrase permutation',
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

  /**
   * Detect ordered synonym sequences like: IGNORE ... PREVIOUS ... INSTRUCTIONS
   * Allows up to maxGap words between terms and uses the SYNONYMS corpus.
   */
  private detectOrderedSynonymSequences(text: string, maxGap: number = 6): DetectionResult[] {
    const results: DetectionResult[] = [];
    const ignoreGroup = this.buildWordGroup(SYNONYMS.ignore);
    const previousGroup = this.buildWordGroup(SYNONYMS.previous);
    const instructionsGroup = this.buildWordGroup(SYNONYMS.instructions);

    // Gap allowing up to N words between tokens
    const gap = `(?:[^\w]+\w+){0,${maxGap}}[^\w]+`;
    const pattern = new RegExp(
      `\\b(?:${ignoreGroup})\\b${gap}\\b(?:${previousGroup})\\b${gap}\\b(?:${instructionsGroup})\\b`,
      'gi'
    );

    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      results.push({
        type: 'prompt-injection',
        severity: 'critical',
        matched: match[0],
        startIndex: start,
        endIndex: end,
        context: 'Ordered synonym sequence detected: ignore → previous → instructions',
      });
    }

    return results;
  }

  /**
   * Build a regex alternation group for words, allowing simple singular/plural variations.
   */
  private buildWordGroup(words: string[]): string {
    const escaped = words.map((w) => {
      const safe = w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // Allow optional trailing 's' if the synonym is plural; crude but effective for our list
      if (/s$/.test(safe)) {
        const base = safe.replace(/s$/, '');
        return `(?:${base}s?)`;
      }
      return safe;
    });
    return escaped.join('|');
  }
}

export const injectionPhrasesDetector = new InjectionPhrasesDetector();
