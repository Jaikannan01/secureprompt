/**
 * Example usage of the corpus generator
 * 
 * This file demonstrates how to use the corpus generator to create
 * permutations of injection phrases using the SYNONYMS table.
 * 
 * Run this at build-time to generate a corpus JSON file.
 */

import { generateCorpus } from './corpusGenerator';
import { SYNONYMS } from '../detectors/corpus/injectionPhrases';

// Example: Generate permutations for common injection phrases
const exampleUsage = () => {
  const result = generateCorpus({
    seeds: [
      'ignore previous instructions',
      'disregard the above',
      'override safety rules',
    ],
    templates: [
      '{ignore} {previous} {instructions}',
      'do not follow {previous} {instructions}',
      '{override} {safety} restrictions',
    ],
    synonyms: SYNONYMS,
    options: {
      maxOutputs: 1000,
      casingVariants: true,
      joinVariants: true,
      leetVariants: true,
      wrapperVariants: true,
      zeroWidthVariants: false,
      maxVariantsPerPhrase: 20,
      shuffle: true,
      seed: 1337,
    },
  });

  console.log(`Generated ${result.phrases.length} phrases`);
  console.log('Meta:', result.meta);
  console.log('Sample phrases:', result.phrases.slice(0, 10));

  // In a real build script, you would write this to a file:
  // import fs from 'fs';
  // fs.writeFileSync('corpus.json', JSON.stringify(result.phrases, null, 2));
};

export { exampleUsage };

