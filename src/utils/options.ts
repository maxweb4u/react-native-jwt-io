/**
 * Option bags are checked for unknown names: a misspelled `expiresin` or
 * jsonwebtoken's `maxAge` would otherwise be ignored, and the check it was
 * meant to switch on would silently not happen.
 * See memory_bank/domain/validation.md#options.
 */

import { isPlainObject } from './json';

function describeOptions(value: unknown): string {
  if (typeof value === 'function') {
    return 'a function (this library has no callbacks: it returns or throws)';
  }
  if (Array.isArray(value)) {
    return 'an array';
  }
  return value !== null && typeof value === 'object' ? 'an object that is not a plain object' : typeof value;
}

/** What other JWT libraries call options this one names differently. */
const ELSEWHERE: Record<string, string> = {
  maxAge: 'This library calls it "maxTokenAge".',
  algorithms: 'This library takes one "algorithm", and an imported key already carries its own.',
  clockTimestamp: 'Pass "now" as a Date.',
  complete: 'verify always returns { header, payload }.',
  ignoreNotBeforeClaim: 'This library calls it "ignoreNotBefore".',
  jwtid: 'This library calls it "jwtId".',
  keyid: 'This library calls it "keyId".',
  expiresin: 'This library calls it "expiresIn".',
  notbefore: 'This library calls it "notBefore".',
};

/**
 * Throws unless `options` is a plain object whose own names are all known.
 * A plain object only: a function (a jsonwebtoken-style callback), a string,
 * a Map or a class instance would otherwise be read as "no options", and
 * options inherited through a prototype would apply without being checked.
 */
export function assertKnownOptions(
  options: unknown,
  known: readonly string[],
  fail: (name: string, message: string) => Error,
): void {
  if (!isPlainObject(options)) {
    throw fail(
      'options',
      `The options must be a plain object, such as { ${known[0] as string}: … }; got ${describeOptions(options)}.`,
    );
  }
  // for…in, not Object.keys: an enumerable name on a null prototype counts too.
  for (const name in options) {
    if (!Object.prototype.hasOwnProperty.call(options, name)) {
      throw fail(name, `The option "${name}" is inherited, not the options object's own; pass a plain object.`);
    }
    if (!known.includes(name)) {
      const hint = Object.prototype.hasOwnProperty.call(ELSEWHERE, name) ? ` ${ELSEWHERE[name] as string}` : '';
      throw fail(name, `Unknown option "${name}".${hint} Known options: ${known.join(', ')}.`);
    }
  }
}
