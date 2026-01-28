# secureprompt.dev

A TypeScript library for sanitizing LLM prompt input/output to prevent sensitive data leaks and injection attacks.

## Installation

```bash
npm install secureprompt.dev
```

## Usage

```typescript
import { sanitizePrompt } from 'secureprompt.dev';

const result = sanitizePrompt('User input/output here');
```

See the main [README.md](../../README.md) for full documentation.
