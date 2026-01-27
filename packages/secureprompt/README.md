# secureprompt

A TypeScript library for sanitizing LLM prompt inputs to prevent sensitive data leaks and injection attacks.

## Installation

```bash
npm install secureprompt
```

## Usage

```typescript
import { sanitizePrompt } from 'secureprompt';

const result = sanitizePrompt('User input here');
```

See the main [README.md](../../README.md) for full documentation.

