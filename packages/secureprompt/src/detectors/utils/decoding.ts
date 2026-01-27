/**
 * Decoding utilities for various obfuscation methods
 */

/**
 * Decode URL-encoded string
 */
export function decodeURL(encoded: string): string | null {
  try {
    return decodeURIComponent(encoded);
  } catch {
    return null;
  }
}

/**
 * Decode hex-encoded string
 */
export function decodeHex(hex: string): string | null {
  try {
    // Remove any non-hex characters and ensure even length
    const cleanHex = hex.replace(/[^0-9A-Fa-f]/g, '');
    if (cleanHex.length % 2 !== 0 || cleanHex.length < 2) {
      return null;
    }
    
    let decoded = '';
    for (let i = 0; i < cleanHex.length; i += 2) {
      const byte = parseInt(cleanHex.substring(i, i + 2), 16);
      if (byte > 127) {
        // Not ASCII, try UTF-8
        return null;
      }
      decoded += String.fromCharCode(byte);
    }
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Decode ROT13-encoded string
 */
export function decodeROT13(encoded: string): string {
  return encoded.replace(/[A-Za-z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : 97; // A-Z or a-z
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

/**
 * Decode Unicode escape sequences (\uXXXX)
 */
export function decodeUnicodeEscapes(encoded: string): string | null {
  try {
    // Replace \uXXXX with actual characters
    return encoded.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  } catch {
    return null;
  }
}

/**
 * Check if a string looks like it could be ROT13-encoded
 * ROT13 only affects letters, so if there are many letters and few other chars, it might be ROT13
 */
export function looksLikeROT13(text: string): boolean {
  const letters = (text.match(/[A-Za-z]/g) || []).length;
  const total = text.length;
  // If more than 80% are letters, it might be ROT13
  return total > 0 && letters / total > 0.8;
}

