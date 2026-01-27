# SecurePrompt Detectors Reference

This document lists all detection patterns currently implemented in SecurePrompt. Use this as a reference when adding new detection patterns.

## Sensitive Data Detector (`sensitive-data`)

| Detection Method | Type | Severity | Pattern/Approach | Description |
|-----------------|------|----------|------------------|-------------|
| `detectCreditCards` | `credit-card` | `critical` | Regex: `/\b(?:\d[ -]?){13,19}\b/g` + Luhn algorithm validation | Detects credit card numbers (13-19 digits) with optional spaces/dashes. Validates using Luhn algorithm to reduce false positives. |
| `detectSSNs` | `ssn` | `critical` | Regex: `/\b\d{3}-?\d{2}-?\d{4}\b/g` + prefix validation | Detects US Social Security Numbers in XXX-XX-XXXX or XXXXXXXXX format. Excludes invalid prefixes (000, 666, 900-999). |
| `detectEmails` | `email` | `medium` | Regex: `/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z\|a-z]{2,}\b/g` | Detects email addresses using standard email pattern matching. |
| `detectPhoneNumbers` | `phone` | `medium` | Regex: `/\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g` | Detects US phone numbers in various formats: (XXX) XXX-XXXX, XXX-XXX-XXXX, XXX.XXX.XXXX, with optional country code. |
| `detectAPIKeys` | `aws-access-key` | `high` | Regex: `/\bAKIA[0-9A-Z]{16}\b/g` | Detects AWS Access Key IDs (starts with AKIA followed by 16 alphanumeric characters). |
| `detectAPIKeys` | `github-token` | `high` | Regex: `/\bghp_[a-zA-Z0-9]{36}\b/g` | Detects GitHub personal access tokens (starts with ghp_ followed by 36 alphanumeric characters). |
| `detectAPIKeys` | `api-key` | `medium` | Regex: `/\b[a-zA-Z0-9]{32,}\b/g` + hash/UUID filter | Detects generic API keys (32+ character alphanumeric strings). Filters out hashes and UUIDs to reduce false positives. |
| `detectIPAddresses` | `ip-address` | `low` | Regex: `/\b(?:(?:25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\b/g` | Detects IPv4 addresses. |

## Injection Pattern Detector (`injection-patterns`)

| Detection Method | Type | Severity | Pattern/Approach | Description |
|-----------------|------|----------|------------------|-------------|
| `detectPromptInjection` | `prompt-injection` | `critical` to `medium` | Exact phrase matching (case-insensitive) | Detects common prompt injection phrases: "ignore previous instructions", "system:", "override safety", "bypass safety", "ignore safety" (critical), "ignore all previous instructions", "disregard the above", "forget everything" (high), "you are now", "act as if", "pretend to be" (medium). |
| `detectJailbreakAttempts` | `jailbreak` | `high` to `medium` | Regex pattern matching (case-insensitive) | Detects jailbreak attempts: "jailbreak", "dan mode", "developer mode", "god mode", "unrestricted mode" (high), "roleplay as", "hypothetical scenario" (medium). |
| `detectSystemPromptExtraction` | `system-prompt-extraction` | `high` | Exact phrase matching (case-insensitive) | Detects attempts to extract system prompts: "show me your instructions", "what are your instructions", "what is your system prompt", "repeat your prompt", "what were you told", "reveal your instructions", "print your instructions", "display your system message", "what is your training data", "show me your training". |
| `detectBase64Encoded` | `base64-encoded-injection` | `high` | Regex: `/\b[A-Za-z0-9+/]{50,}={0,2}\b/g` + decode + keyword check | Detects Base64-encoded injection attempts. Finds Base64 strings (50+ chars), decodes them, and checks for keywords: "ignore", "system", "jailbreak". Works in both Node.js (Buffer) and browser (atob). |
| `detectUnicodeObfuscation` | `unicode-obfuscation` | `medium` | Regex: `/[\u200B-\u200D\uFEFF\u00AD\u2060-\u206F\u202A-\u202E]/g` + count threshold | Detects Unicode obfuscation attempts. Looks for suspicious Unicode characters (zero-width spaces, directional marks, etc.). Flags if more than 5 suspicious characters found. |

## Adding New Detection Patterns

To add a new detection pattern:

1. **For Sensitive Data**: Add a new method to `SensitiveDataDetector` class in `src/detectors/sensitiveData.ts`
2. **For Injection Patterns**: Add a new method to `InjectionPatternDetector` class in `src/detectors/injectionPatterns.ts`
3. **For New Detector Type**: Create a new detector class implementing the `Detector` interface in `src/detectors/baseDetector.ts`

### Detection Method Template

```typescript
private detectNewPattern(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  // Your detection logic here
  const pattern = /your-regex-pattern/g;
  let match;
  
  while ((match = pattern.exec(text)) !== null) {
    // Optional: Add validation logic
    results.push({
      type: 'your-detection-type',
      severity: 'high', // or 'critical', 'medium', 'low'
      matched: match[0],
      startIndex: match.index,
      endIndex: match.index + match[0].length,
      context: 'Description of what was detected',
    });
  }
  
  return results;
}
```

### Registering New Detection Methods

Don't forget to call your new detection method in the `detect()` function:

```typescript
detect(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  // ... existing detections
  results.push(...this.detectNewPattern(text));
  return results;
}
```

## Notes

- **Severity Levels**: `critical` > `high` > `medium` > `low`
- **Blocking Logic**: Inputs with `critical` or `high` severity violations are blocked when `action === 'block'`
- **Redaction**: Violations are redacted in reverse order (end to start) to preserve string indices
- **False Positives**: Consider adding validation logic (like Luhn for credit cards) to reduce false positives
- **Performance**: Keep regex patterns efficient and avoid catastrophic backtracking

