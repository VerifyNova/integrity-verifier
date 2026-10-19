import {
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';

/**
 * UnifyID's published checkpoint signing keys, as a JWKS-style document, and
 * the ES256 (ECDSA P-256 with SHA-256) check of a checkpoint signature.
 *
 * The verifier never fetches keys by itself: the caller passes a key set it
 * obtained and chose to trust (from a file, or fetched once from UnifyID's
 * public keys URL). A key is matched by `kid` only; a key without the P-256
 * curve is refused.
 */

export type PublishedKey = JsonWebKey & {
  kid: string;
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  alg?: 'ES256';
  use?: 'sig';
  /** When the key started and stopped signing checkpoints, if the key set says so. */
  notBefore?: string | null;
  notAfter?: string | null;
  status?: string;
};

export type KeySet = { keys: PublishedKey[] };

export function parseKeySet(input: unknown): KeySet {
  const value =
    input && typeof input === 'object' && 'data' in (input as object)
      ? (input as { data: unknown }).data
      : input;
  const keys = Array.isArray(value)
    ? value
    : value && typeof value === 'object' && Array.isArray((value as { keys?: unknown }).keys)
      ? (value as { keys: unknown[] }).keys
      : null;
  if (!keys) throw new TypeError('The key set must be a JSON object with a "keys" array.');
  const valid = keys.filter(
    (key): key is PublishedKey =>
      !!key &&
      typeof key === 'object' &&
      (key as PublishedKey).kty === 'EC' &&
      (key as PublishedKey).crv === 'P-256' &&
      typeof (key as PublishedKey).kid === 'string' &&
      typeof (key as PublishedKey).x === 'string' &&
      typeof (key as PublishedKey).y === 'string',
  );
  return { keys: valid };
}

export function findKey(keySet: KeySet, keyId: string): PublishedKey | null {
  return keySet.keys.find((key) => key.kid === keyId) ?? null;
}

export function publicKeyObject(key: PublishedKey): KeyObject {
  return createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: key.x, y: key.y },
    format: 'jwk',
  });
}

/**
 * ES256 over `data`. Accepts the signature as base64url, base64 or 0x-hex, in
 * either the 64-byte r||s form (JOSE, and what the contracts store) or DER
 * (what AWS KMS returns).
 */
export function verifyEs256(
  data: Uint8Array,
  signature: string | Uint8Array,
  key: PublishedKey,
): boolean {
  try {
    const bytes =
      typeof signature === 'string' ? decodeSignature(signature) : Buffer.from(signature);
    const encoding = bytes.length === 64 ? 'ieee-p1363' : 'der';
    return verifySignature(
      'sha256',
      data,
      { key: publicKeyObject(key), dsaEncoding: encoding },
      bytes,
    );
  } catch {
    return false;
  }
}

function decodeSignature(value: string): Buffer {
  const text = value.trim();
  if (/^0x[0-9a-f]+$/i.test(text)) return Buffer.from(text.slice(2), 'hex');
  if (/^[A-Za-z0-9_-]+$/.test(text)) return Buffer.from(text, 'base64url');
  return Buffer.from(text, 'base64');
}

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** True when a 64-byte r||s signature has s at most n/2, the one canonical form UnifyID publishes. */
export function isLowS(signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  const s = BigInt(`0x${Buffer.from(signature).subarray(32).toString('hex')}`);
  return s > 0n && s <= P256_N / 2n;
}

/** The same signature with s at most n/2. */
export function toLowS(signature: Uint8Array): Buffer {
  const raw = Buffer.from(signature);
  if (raw.length !== 64) throw new RangeError('A P-256 signature is 64 bytes r || s.');
  const s = BigInt(`0x${raw.subarray(32).toString('hex')}`);
  if (s <= P256_N / 2n) return raw;
  return Buffer.concat([
    raw.subarray(0, 32),
    Buffer.from((P256_N - s).toString(16).padStart(64, '0'), 'hex'),
  ]);
}

/** RFC 7638 thumbprint input for an EC key, so a key can be named independently of its kid. */
export function thumbprintInput(key: Pick<PublishedKey, 'crv' | 'kty' | 'x' | 'y'>): string {
  return JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y });
}
