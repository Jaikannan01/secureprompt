/**
 * Corpus Generator
 * 
 * Generate a large corpus of prompt-injection / jailbreak phrase permutations.
 * Intended to run at build-time (Node) and then ship the resulting JSON to runtime.
 * 
 * Usage example:
 *   import { generateCorpus } from './utils/corpusGenerator';
 *   import { SYNONYMS } from '../detectors/corpus/injectionPhrases';
 *   
 *   const { phrases } = generateCorpus({
 *     seeds: ['ignore previous instructions'],
 *     templates: ['{ignore} {previous} {instructions}'],
 *     synonyms: SYNONYMS,
 *     options: { maxOutputs: 5000 }
 *   });
 *   fs.writeFileSync("corpus.json", JSON.stringify(phrases, null, 2));
 */

export type SynonymMap = Record<string, string[]>;

export type GeneratorOptions = {
  /** Max number of outputs total (after dedupe). */
  maxOutputs?: number;
  /** Add casing variants (lower/upper/title). */
  casingVariants?: boolean;
  /** Add spacing/punctuation join variants. */
  joinVariants?: boolean;
  /** Add light leetspeak variants. */
  leetVariants?: boolean;
  /** Add per-word quoted/bracketed variants. */
  wrapperVariants?: boolean;
  /** Inject zero-width chars between letters (use sparingly). */
  zeroWidthVariants?: boolean;
  /** Cap expansions per base phrase before global dedupe. */
  maxVariantsPerPhrase?: number;
  /** Randomize & truncate (useful to control size). */
  shuffle?: boolean;
  /** Seed for deterministic shuffle. */
  seed?: number;
};

export type CorpusInput = {
  seeds: string[];
  /**
   * Templates like:
   *   "{ignore} {previous} {instructions}"
   *   "do not follow {previous} {instructions}"
   */
  templates?: string[];
  synonyms?: SynonymMap;
  options?: GeneratorOptions;
};

export type CorpusOutput = {
  phrases: string[];
  meta: {
    inputSeedCount: number;
    templateCount: number;
    synonymKeys: string[];
    generatedBeforeDedupe: number;
    dedupedCount: number;
    truncatedToMax?: number;
  };
};

const DEFAULT_OPTIONS: Required<GeneratorOptions> = {
  maxOutputs: 5000,
  casingVariants: true,
  joinVariants: true,
  leetVariants: true,
  wrapperVariants: true,
  zeroWidthVariants: false, // default off: only enable if you really want
  maxVariantsPerPhrase: 40,
  shuffle: true,
  seed: 1337,
};

/** Deterministic PRNG for shuffling (Mulberry32). */
function mulberry32(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seededShuffle<T>(arr: T[], seed: number): T[] {
  const rand = mulberry32(seed);
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * Normalization for dedupe:
 * - NFKC normalize
 * - lowercase
 * - collapse whitespace
 * - trim
 */
export function canonicalize(s: string): string {
  return s
    .normalize('NFKC')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/** Title case for quick casing variant. */
function toTitleCase(s: string): string {
  return s
    .split(/\s+/g)
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1).toLowerCase() : w))
    .join(' ');
}

/** Light leet mapping (keep small so variants don't explode). */
const LEET: Record<string, string[]> = {
  a: ['a', '4', '@'],
  e: ['e', '3'],
  i: ['i', '1', '!'],
  o: ['o', '0'],
  s: ['s', '5', '$'],
  t: ['t', '7'],
};

function leetifyOnce(s: string): string[] {
  // Generate a few leet variants by replacing some characters, not all.
  const out = new Set<string>();
  out.add(s);

  // Replace up to N chars per phrase to avoid explosion
  const chars = s.split('');
  const positions: number[] = [];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i].toLowerCase();
    if (LEET[c]) positions.push(i);
  }
  const maxReplacements = Math.min(3, positions.length);
  for (let r = 1; r <= maxReplacements; r++) {
    for (let k = 0; k < positions.length; k++) {
      const i = positions[k];
      const c = chars[i].toLowerCase();
      const alts = LEET[c];
      if (!alts) continue;
      for (const alt of alts) {
        if (alt === chars[i]) continue;
        const copy = chars.slice();
        copy[i] = alt;
        out.add(copy.join(''));
      }
    }
  }
  return Array.from(out);
}

function wrapVariants(s: string): string[] {
  return [
    s,
    `"${s}"`,
    `'${s}'`,
    `(${s})`,
    `[${s}]`,
    `{${s}}`,
    `<<<${s}>>>`,
    `### ${s} ###`,
  ];
}

function casingVariants(s: string): string[] {
  return [s, s.toLowerCase(), s.toUpperCase(), toTitleCase(s)];
}

/** Join / separator variants between words. */
function joinVariants(s: string): string[] {
  const words = s.split(/\s+/g).filter(Boolean);
  if (words.length <= 1) return [s];

  const joins = [
    ' ', // normal
    '  ', // extra spaces
    '\n', // newline
    '\t', // tab
    '-',
    '_',
    '.',
    '/',
    '\\',
    ':',
    ';',
    '|',
    ',',
  ];

  const out = new Set<string>();
  for (const j of joins) {
    out.add(words.join(j));
  }
  // collapsed, e.g. ignorepreviousinstructions
  out.add(words.join(''));
  return Array.from(out);
}

function zeroWidthInject(s: string): string {
  // insert ZWSP between some letters (very light)
  const zwsp = '\u200B';
  let out = '';
  for (let i = 0; i < s.length; i++) {
    out += s[i];
    if (i % 3 === 1 && /[a-zA-Z]/.test(s[i])) out += zwsp;
  }
  return out;
}

/**
 * Expand templates using synonyms.
 * Example template: "{ignore} {previous} {instructions}"
 */
function expandTemplates(templates: string[], synonyms: SynonymMap): string[] {
  const keys = Object.keys(synonyms ?? {});
  if (!templates.length || !keys.length) return [];

  const out: string[] = [];

  for (const tpl of templates) {
    // Find placeholders used in this template
    const matches = Array.from(tpl.matchAll(/\{([a-zA-Z0-9_]+)\}/g));
    const used = matches.map((m) => m[1]);
    const uniqUsed = Array.from(new Set(used));

    // If any placeholder missing, skip
    if (uniqUsed.some((k) => !synonyms[k] || !synonyms[k].length)) continue;

    // Cartesian product over used keys (bounded by reasonable limits)
    const pools = uniqUsed.map((k) => synonyms[k]);

    // Iterative product
    let combos: Record<string, string>[] = [{}];
    for (let i = 0; i < uniqUsed.length; i++) {
      const key = uniqUsed[i];
      const pool = pools[i];

      const next: Record<string, string>[] = [];
      for (const c of combos) {
        for (const val of pool) {
          next.push({ ...c, [key]: val });
          // soft cap per template to prevent explosion
          if (next.length > 2000) break;
        }
        if (next.length > 2000) break;
      }
      combos = next;
      if (combos.length > 2000) break;
    }

    for (const combo of combos) {
      let phrase = tpl;
      for (const [k, v] of Object.entries(combo)) {
        phrase = phrase.replaceAll(`{${k}}`, v);
      }
      // Clean spaces that may result from substitutions
      phrase = phrase.replace(/\s+/g, ' ').trim();
      out.push(phrase);
    }
  }

  return out;
}

function variantsForPhrase(
  base: string,
  opt: Required<GeneratorOptions>
): string[] {
  let current = new Set<string>();
  current.add(base);

  // join/separator variants
  if (opt.joinVariants) {
    const next = new Set<string>();
    for (const s of current) for (const v of joinVariants(s)) next.add(v);
    current = next;
  }

  // wrapper variants
  if (opt.wrapperVariants) {
    const next = new Set<string>();
    for (const s of current) for (const v of wrapVariants(s)) next.add(v);
    current = next;
  }

  // casing variants
  if (opt.casingVariants) {
    const next = new Set<string>();
    for (const s of current) for (const v of casingVariants(s)) next.add(v);
    current = next;
  }

  // leet variants (light)
  if (opt.leetVariants) {
    const next = new Set<string>();
    for (const s of current) {
      for (const v of leetifyOnce(s)) next.add(v);
    }
    current = next;
  }

  // zero-width injection (optional)
  if (opt.zeroWidthVariants) {
    const next = new Set<string>(current);
    for (const s of current) next.add(zeroWidthInject(s));
    current = next;
  }

  // Cap per phrase
  const arr = Array.from(current);
  if (arr.length > opt.maxVariantsPerPhrase) {
    // deterministic truncate by sorting canonical
    arr.sort((a, b) => canonicalize(a).localeCompare(canonicalize(b)));
    return arr.slice(0, opt.maxVariantsPerPhrase);
  }
  return arr;
}

export function generateCorpus(input: CorpusInput): CorpusOutput {
  const opt: Required<GeneratorOptions> = {
    ...DEFAULT_OPTIONS,
    ...(input.options ?? {}),
  };

  const seeds = (input.seeds ?? [])
    .map((s) => s.trim())
    .filter(Boolean);
  const templates = (input.templates ?? [])
    .map((t) => t.trim())
    .filter(Boolean);
  const synonyms = input.synonyms ?? {};

  const fromTemplates = expandTemplates(templates, synonyms);

  const basePhrases = Array.from(new Set([...seeds, ...fromTemplates]))
    .map((p) => p.replace(/\s+/g, ' ').trim())
    .filter(Boolean);

  let generatedBeforeDedupe = 0;

  // Generate variants
  const all: string[] = [];
  for (const base of basePhrases) {
    const vars = variantsForPhrase(base, opt);
    generatedBeforeDedupe += vars.length;
    all.push(...vars);
  }

  // Dedupe by canonical form, but keep original surface forms
  const seen = new Set<string>();
  const deduped: string[] = [];
  for (const s of all) {
    const key = canonicalize(s);
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(s);
  }

  let phrases = deduped;

  if (opt.shuffle) phrases = seededShuffle(phrases, opt.seed);

  let truncatedToMax: number | undefined;
  if (phrases.length > opt.maxOutputs) {
    truncatedToMax = opt.maxOutputs;
    phrases = phrases.slice(0, opt.maxOutputs);
  }

  return {
    phrases,
    meta: {
      inputSeedCount: seeds.length,
      templateCount: templates.length,
      synonymKeys: Object.keys(synonyms),
      generatedBeforeDedupe,
      dedupedCount: deduped.length,
      truncatedToMax,
    },
  };
}

