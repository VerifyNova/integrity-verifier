import { createHash } from 'node:crypto';

/**
 * RFC 6962 / RFC 9162 Merkle tree arithmetic: leaf and node hashing, and the
 * verification of inclusion and consistency proofs exactly as RFC 9162
 * sections 2.1.3.2 and 2.1.4.2 describe them.
 *
 * Hashes travel as lowercase hex strings. Sizes and indices are accepted as
 * numbers, bigints or decimal strings; they are handled as bigints so a very
 * large log never loses precision.
 *
 * The generator functions (`merkleTreeHash`, `inclusionPath`,
 * `consistencyProof`) exist so tests and third parties can build fixtures;
 * verification never needs them.
 */

export type Hex = string;
export type Size = number | bigint | string;

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function toBigInt(value: Size, name: string): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0)
      throw new TypeError(`${name} must be a non-negative integer.`);
    return BigInt(value);
  }
  if (typeof value === 'string' && /^\d+$/.test(value)) return BigInt(value);
  throw new TypeError(`${name} must be a non-negative integer.`);
}

function bytes(hash: Hex, name = 'hash'): Buffer {
  const normalized = hash
    .toLowerCase()
    .replace(/^0x/, '')
    .replace(/^sha256:/, '');
  if (!/^[a-f0-9]{64}$/.test(normalized))
    throw new TypeError(`${name} must be a SHA-256 hex digest.`);
  return Buffer.from(normalized, 'hex');
}

export function isHash(value: unknown): value is Hex {
  return typeof value === 'string' && /^(0x)?[a-f0-9]{64}$/i.test(value);
}

export function normalizeHex(hash: Hex): Hex {
  return bytes(hash).toString('hex');
}

/** MTH({d}) = SHA-256(0x00 || d): the hash of one leaf's bytes. */
export function leafHash(data: Uint8Array | string): Hex {
  const input = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return createHash('sha256').update(LEAF_PREFIX).update(input).digest('hex');
}

/** SHA-256(0x01 || left || right): an interior node. */
export function nodeHash(left: Hex, right: Hex): Hex {
  return createHash('sha256')
    .update(NODE_PREFIX)
    .update(bytes(left, 'left'))
    .update(bytes(right, 'right'))
    .digest('hex');
}

/** The hash of the empty tree, SHA-256 of nothing. */
export const EMPTY_TREE_HASH: Hex = createHash('sha256').digest('hex');

/** RFC 9162 2.1.3.2: does `leaf` sit at `index` in the tree of `treeSize` leaves whose root is `root`? */
export function verifyInclusion(input: {
  leafHash: Hex;
  index: Size;
  treeSize: Size;
  path: readonly Hex[];
  root: Hex;
}): boolean {
  try {
    const index = toBigInt(input.index, 'index');
    const size = toBigInt(input.treeSize, 'treeSize');
    if (index >= size) return false;
    let fn = index;
    let sn = size - 1n;
    let r = normalizeHex(input.leafHash);
    for (const p of input.path) {
      if (sn === 0n) return false;
      if ((fn & 1n) === 1n || fn === sn) {
        r = nodeHash(p, r);
        if ((fn & 1n) === 0n)
          while ((fn & 1n) === 0n && fn !== 0n) {
            fn >>= 1n;
            sn >>= 1n;
          }
      } else {
        r = nodeHash(r, p);
      }
      fn >>= 1n;
      sn >>= 1n;
    }
    return sn === 0n && safeEqual(r, input.root);
  } catch {
    return false;
  }
}

/** RFC 9162 2.1.4.2: is the tree of `secondSize` leaves an append-only extension of the tree of `firstSize`? */
export function verifyConsistency(input: {
  firstSize: Size;
  secondSize: Size;
  firstRoot: Hex;
  secondRoot: Hex;
  proof: readonly Hex[];
}): boolean {
  try {
    const first = toBigInt(input.firstSize, 'firstSize');
    const second = toBigInt(input.secondSize, 'secondSize');
    if (first > second) return false;
    if (first === second)
      return input.proof.length === 0 && safeEqual(input.firstRoot, input.secondRoot);
    if (first === 0n) return input.proof.length === 0;
    if (!input.proof.length) return false;
    const path = [...input.proof];
    if ((first & (first - 1n)) === 0n) path.unshift(input.firstRoot);
    let fn = first - 1n;
    let sn = second - 1n;
    while ((fn & 1n) === 1n) {
      fn >>= 1n;
      sn >>= 1n;
    }
    let fr = normalizeHex(path[0]!);
    let sr = fr;
    for (const c of path.slice(1)) {
      if (sn === 0n) return false;
      if ((fn & 1n) === 1n || fn === sn) {
        fr = nodeHash(c, fr);
        sr = nodeHash(c, sr);
        if ((fn & 1n) === 0n)
          while ((fn & 1n) === 0n && fn !== 0n) {
            fn >>= 1n;
            sn >>= 1n;
          }
      } else {
        sr = nodeHash(sr, c);
      }
      fn >>= 1n;
      sn >>= 1n;
    }
    return safeEqual(fr, input.firstRoot) && safeEqual(sr, input.secondRoot) && sn === 0n;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- generators

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

/** MTH(D[n]) over already-hashed leaves. */
export function merkleTreeHash(leaves: readonly Hex[]): Hex {
  if (leaves.length === 0) return EMPTY_TREE_HASH;
  if (leaves.length === 1) return normalizeHex(leaves[0]!);
  const k = largestPowerOfTwoBelow(leaves.length);
  return nodeHash(merkleTreeHash(leaves.slice(0, k)), merkleTreeHash(leaves.slice(k)));
}

/** PATH(m, D[n]) over already-hashed leaves. */
export function inclusionPath(index: number, leaves: readonly Hex[]): Hex[] {
  if (index < 0 || index >= leaves.length) throw new RangeError('index is outside the tree.');
  if (leaves.length === 1) return [];
  const k = largestPowerOfTwoBelow(leaves.length);
  if (index < k)
    return [...inclusionPath(index, leaves.slice(0, k)), merkleTreeHash(leaves.slice(k))];
  return [...inclusionPath(index - k, leaves.slice(k)), merkleTreeHash(leaves.slice(0, k))];
}

/** PROOF(m, D[n]) over already-hashed leaves. */
export function consistencyProof(firstSize: number, leaves: readonly Hex[]): Hex[] {
  if (firstSize < 0 || firstSize > leaves.length)
    throw new RangeError('firstSize is outside the tree.');
  if (firstSize === 0 || firstSize === leaves.length) return [];
  return subproof(firstSize, leaves, true);
}

function subproof(m: number, leaves: readonly Hex[], complete: boolean): Hex[] {
  const n = leaves.length;
  if (m === n) return complete ? [] : [merkleTreeHash(leaves)];
  const k = largestPowerOfTwoBelow(n);
  if (m <= k)
    return [...subproof(m, leaves.slice(0, k), complete), merkleTreeHash(leaves.slice(k))];
  return [...subproof(m - k, leaves.slice(k), false), merkleTreeHash(leaves.slice(0, k))];
}

export function safeEqual(left: Hex, right: Hex): boolean {
  try {
    const a = bytes(left);
    const b = bytes(right);
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
    return diff === 0;
  } catch {
    return false;
  }
}
