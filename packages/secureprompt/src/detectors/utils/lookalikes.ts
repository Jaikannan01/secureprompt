/**
 * Lookalike character detection utilities
 * Maps confusable characters (Cyrillic, Greek, etc.) to ASCII equivalents
 */

/**
 * Critical keywords that attackers might try to obfuscate with lookalike characters
 */
export const CRITICAL_KEYWORDS = [
  'system',
  'developer',
  'ignore',
  'override',
  'instructions',
  'bypass',
  'jailbreak',
];

/**
 * Mapping of confusable characters to their ASCII equivalents
 * Includes Cyrillic, Greek, and other Unicode characters that look like ASCII
 */
const LOOKALIKE_MAP: Record<string, string> = {
  // Cyrillic lookalikes
  '\u0430': 'a', // а (Cyrillic small a)
  '\u0435': 'e', // е (Cyrillic small e)
  '\u043E': 'o', // о (Cyrillic small o)
  '\u0440': 'p', // р (Cyrillic small p)
  '\u0441': 'c', // с (Cyrillic small c)
  '\u0443': 'y', // у (Cyrillic small u)
  '\u0445': 'x', // х (Cyrillic small ha)
  '\u0410': 'A', // А (Cyrillic capital A)
  '\u0412': 'B', // В (Cyrillic capital Ve)
  '\u0415': 'E', // Е (Cyrillic capital E)
  '\u041A': 'K', // К (Cyrillic capital Ka)
  '\u041C': 'M', // М (Cyrillic capital Em)
  '\u041E': 'O', // О (Cyrillic capital O)
  '\u0420': 'P', // Р (Cyrillic capital Er)
  '\u0421': 'C', // С (Cyrillic capital Es)
  '\u0422': 'T', // Т (Cyrillic capital Te)
  '\u0423': 'Y', // У (Cyrillic capital U)
  '\u0425': 'X', // Х (Cyrillic capital Ha)
  
  // Greek lookalikes
  '\u03B1': 'a', // α (Greek small alpha)
  '\u03B5': 'e', // ε (Greek small epsilon)
  '\u03BF': 'o', // ο (Greek small omicron)
  '\u03C1': 'p', // ρ (Greek small rho)
  '\u03C5': 'u', // υ (Greek small upsilon)
  '\u03C7': 'x', // χ (Greek small chi)
  '\u0391': 'A', // Α (Greek capital Alpha)
  '\u0392': 'B', // Β (Greek capital Beta)
  '\u0395': 'E', // Ε (Greek capital Epsilon)
  '\u039A': 'K', // Κ (Greek capital Kappa)
  '\u039C': 'M', // Μ (Greek capital Mu)
  '\u039F': 'O', // Ο (Greek capital Omicron)
  '\u03A1': 'P', // Ρ (Greek capital Rho)
  '\u03A4': 'T', // Τ (Greek capital Tau)
  '\u03A7': 'X', // Χ (Greek capital Chi)
  
  // Other confusables
  '\u0131': 'i', // ı (Latin small dotless i)
  '\u0237': 'j', // ȷ (Latin small dotless j)
  '\u00E5': 'a', // å (Latin small a with ring above)
  '\u00F8': 'o', // ø (Latin small o with stroke)
  '\u0142': 'l', // ł (Latin small l with stroke)
  '\u00DF': 's', // ß (Latin small sharp s)
};

/**
 * Normalize text by replacing lookalike characters with ASCII equivalents
 */
export function normalizeLookalikes(text: string): string {
  let normalized = text;
  for (const [lookalike, ascii] of Object.entries(LOOKALIKE_MAP)) {
    normalized = normalized.replace(new RegExp(lookalike, 'g'), ascii);
  }
  return normalized;
}

/**
 * Check if text contains lookalike characters in critical keywords
 */
export function containsLookalikeKeywords(text: string): boolean {
  const normalized = normalizeLookalikes(text.toLowerCase());
  
  // Check if normalized text contains any critical keywords
  return CRITICAL_KEYWORDS.some(keyword => normalized.includes(keyword));
}

/**
 * Find lookalike keyword matches in text
 * Returns the original matched substring and which keyword was found
 */
export function findLookalikeKeywords(text: string): Array<{ keyword: string; matched: string; startIndex: number; endIndex: number }> {
  const results: Array<{ keyword: string; matched: string; startIndex: number; endIndex: number }> = [];
  const lowerText = text.toLowerCase();
  const normalized = normalizeLookalikes(lowerText);
  
  for (const keyword of CRITICAL_KEYWORDS) {
    let searchIndex = 0;
    while (true) {
      const index = normalized.indexOf(keyword, searchIndex);
      if (index === -1) break;
      
      // Get the substring from the original text at the same position
      // Account for potential length differences by using a window
      const windowStart = Math.max(0, index - 2);
      const windowEnd = Math.min(lowerText.length, index + keyword.length + 2);
      const originalSubstring = lowerText.substring(windowStart, windowEnd);
      
      // Check if the original substring contains lookalike characters
      // by comparing normalized version
      const normalizedSubstring = normalizeLookalikes(originalSubstring);
      if (normalizedSubstring.includes(keyword)) {
        // Find the actual position of the keyword in the original substring
        const keywordPosInSubstring = normalizedSubstring.indexOf(keyword);
        const actualStart = windowStart + keywordPosInSubstring;
        const actualEnd = actualStart + keyword.length;
        
        // Get a bit more context for the matched string
        const contextStart = Math.max(0, actualStart - 2);
        const contextEnd = Math.min(lowerText.length, actualEnd + 2);
        
        results.push({
          keyword,
          matched: text.substring(contextStart, contextEnd),
          startIndex: contextStart,
          endIndex: contextEnd,
        });
      }
      
      searchIndex = index + 1;
    }
  }
  
  return results;
}

