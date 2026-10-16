type JsonObject = Record<string, unknown>;

/**
 * `JSON.parse` that drops `__proto__` keys at every depth, so a hostile
 * payload copied with `Object.assign` or a spread cannot reach a prototype.
 * See memory_bank/domain/token-model.md#payload.
 */
export function parseJson(text: string): unknown {
  return JSON.parse(text, (key, value: unknown) => (key === '__proto__' ? undefined : value));
}

/**
 * Freezes a parsed JSON value and everything inside it. Iterative, so nesting
 * that `JSON.parse` accepted cannot overflow the stack here.
 */
export function deepFreeze<T>(value: T): T {
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const item = pending.pop();
    if (item !== null && typeof item === 'object' && !Object.isFrozen(item)) {
      Object.freeze(item);
      // One at a time: a spread of a 30 000-element array is an argument list that long.
      for (const child of Object.values(item)) {
        pending.push(child);
      }
    }
  }
  return value;
}

export function isPlainObject(value: unknown): value is JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  // `Object.prototype` of any realm: its own prototype is null. Comparing with
  // this realm's `Object.prototype` would reject objects from another one,
  // such as the JWKs Node's crypto exports.
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === null || Object.getPrototypeOf(proto) === null;
}
