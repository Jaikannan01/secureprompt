/**
 * Validate that the input is a string
 */
export function validateInput(input: unknown): asserts input is string {
  if (typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }
}

/**
 * Validate that the input is not empty
 */
export function validateNonEmpty(input: string): void {
  if (input.trim().length === 0) {
    throw new Error('Input cannot be empty');
  }
}

/**
 * Luhn algorithm for credit card validation
 * @param cardNumber Credit card number (digits only)
 * @returns true if the card number is valid according to Luhn algorithm
 */
export function luhnCheck(cardNumber: string): boolean {
  // Remove all non-digit characters
  const digits = cardNumber.replace(/\D/g, '');
  
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }

  let sum = 0;
  let isEven = false;

  // Process digits from right to left
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

