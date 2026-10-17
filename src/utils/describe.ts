/**
 * An untrusted value as text for an error message. Never throws: `String()`
 * and template literals throw for an object without a prototype or a symbol,
 * and `JSON.stringify` for a BigInt or a cycle — and an error message must
 * never become a TypeError of its own.
 */
export function describeValue(value: unknown): string {
  if (typeof value === 'string') {
    return escapeLineBreaks(JSON.stringify(value.length > 64 ? `${value.slice(0, 64)}…` : value));
  }
  if (typeof value === 'object' && value !== null) {
    try {
      const text = JSON.stringify(value);
      if (typeof text === 'string') {
        return escapeLineBreaks(text.length > 64 ? `${text.slice(0, 64)}…` : text);
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

/**
 * JSON.stringify escapes C0 controls but not DEL, the C1 controls (U+0085 is a
 * line break to some log viewers, U+009B starts an ANSI sequence), U+2028 and
 * U+2029, or the bidirectional and invisible format characters. Untrusted
 * text — an unverified token's alg or kid — must not be able to start a new
 * line in an app's logs, or reverse the rest of one in a log viewer.
 */
function escapeLineBreaks(text: string): string {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    out += isUnsafe(unit) ? `\\u${unit.toString(16).padStart(4, '0')}` : text[i];
  }
  return out;
}

function isUnsafe(unit: number): boolean {
  return (
    (unit >= 0x7f && unit <= 0x9f) ||
    unit === 0x061c || // Arabic letter mark
    (unit >= 0x200b && unit <= 0x200f) || // zero-width space, joiners, LRM, RLM
    (unit >= 0x2028 && unit <= 0x202e) || // line and paragraph separators, LRE…RLO
    (unit >= 0x2060 && unit <= 0x2069) || // word joiner, invisible operators, LRI…PDI
    unit === 0xfeff // zero-width no-break space (BOM)
  );
}
