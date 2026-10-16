/**
 * An untrusted value as text for an error message. Never throws: `String()`
 * and template literals throw for an object without a prototype or a symbol,
 * and `JSON.stringify` for a BigInt or a cycle — and an error message must
 * never become a TypeError of its own.
 */
export function describeValue(value: unknown): string {
  if (typeof value === 'string') {
    return JSON.stringify(value.length > 64 ? `${value.slice(0, 64)}…` : value);
  }
  if (typeof value === 'object' && value !== null) {
    try {
      const text = JSON.stringify(value);
      if (typeof text === 'string') {
        return text.length > 64 ? `${text.slice(0, 64)}…` : text;
      }
    } catch {
      // fall through
    }
    return Array.isArray(value) ? 'an array' : 'an object';
  }
  if (typeof value === 'function') {
    return 'a function';
  }
  if (typeof value === 'symbol') {
    return 'a symbol';
  }
  return String(value);
}
