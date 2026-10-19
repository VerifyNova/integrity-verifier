import { createHash } from 'node:crypto';
import { EMPTY_TREE_HASH, normalizeHex, safeEqual, type Hex } from './merkle.js';
import type { PublishedKey } from './keys.js';

/**
 * The UnifyID checkpoint statement, version 1: exactly 256 bytes, the Solidity
 * ABI encoding of eight static words
 *
 *   (uint16 version, bytes32 logId, uint64 sequence, uint64 periodStart,
 *    uint64 periodEnd, bytes32 combinedRoot, bytes32 previousCombinedRoot,
 *    bytes32 signingKeyFingerprint)
 *
 * The same bytes are signed once by the checkpoint key (ES256 over
 * SHA-256(statement)), stored by UnifyID, published to UnifyID's anchor
 * contract and attested on Sign Protocol. `fingerprint = SHA-256(statement)`
 * names the checkpoint everywhere.
 */

export const STATEMENT_VERSION = 1;
export const STATEMENT_LENGTH = 256;

/** The sealed streams, in the fixed order the combined root commits to them (statement version 1). */
export const SEALED_STREAMS = [
  'audit',
  'access',
  'disclosure',
  'receipts',
  'transparency',
] as const;
export type SealedStream = (typeof SEALED_STREAMS)[number];

export interface DecodedStatement {
  version: number;
  logId: Hex;
  sequence: string;
  periodStart: string;
  periodEnd: string;
  combinedRoot: Hex;
  /** Null when the statement carries 32 zero bytes (the first checkpoint). */
  previousCombinedRoot: Hex | null;
  signingKeyFingerprint: Hex;
}

export interface StreamHead {
  stream: string;
  treeSize: string;
  rootHash: Hex;
}

const ZERO = '0'.repeat(64);

export function sha256Hex(data: Uint8Array | string): Hex {
  return createHash('sha256')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
    .digest('hex');
}

export function hexToBytes(value: string): Buffer {
  const text = value.trim().replace(/^0x/i, '');
  if (text.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(text))
    throw new TypeError('Expected hex bytes.');
  return Buffer.from(text, 'hex');
}

function word(bytes: Buffer, index: number): Buffer {
  return bytes.subarray(index * 32, (index + 1) * 32);
}

function uintWord(bytes: Buffer, index: number, maxBits: number): bigint {
  const value = BigInt(`0x${word(bytes, index).toString('hex')}`);
  if (value >> BigInt(maxBits) !== 0n)
    throw new TypeError(`Statement word ${index} exceeds uint${maxBits}.`);
  return value;
}

/** Decodes a version 1 statement. Throws on any length, version or width violation. */
export function decodeStatement(statement: string | Uint8Array): DecodedStatement {
  const bytes = typeof statement === 'string' ? hexToBytes(statement) : Buffer.from(statement);
  if (bytes.length !== STATEMENT_LENGTH)
    throw new TypeError(`A statement is ${STATEMENT_LENGTH} bytes.`);
  const version = Number(uintWord(bytes, 0, 16));
  if (version !== STATEMENT_VERSION)
    throw new TypeError(`Statement version ${version} is not supported.`);
  const previous = word(bytes, 6).toString('hex');
  return {
    version,
    logId: word(bytes, 1).toString('hex'),
    sequence: uintWord(bytes, 2, 64).toString(),
    periodStart: uintWord(bytes, 3, 64).toString(),
    periodEnd: uintWord(bytes, 4, 64).toString(),
    combinedRoot: word(bytes, 5).toString('hex'),
    previousCombinedRoot: previous === ZERO ? null : previous,
    signingKeyFingerprint: word(bytes, 7).toString('hex'),
  };
}

/** Encodes a version 1 statement; used by tests and fixtures. */
export function encodeStatement(
  input: Omit<DecodedStatement, 'version'> & { version?: number },
): Buffer {
  const uint = (value: string | number | bigint) => {
    const hex = BigInt(value).toString(16);
    if (hex.length > 64) throw new RangeError('value too large');
    return Buffer.from(hex.padStart(64, '0'), 'hex');
  };
  return Buffer.concat([
    uint(input.version ?? STATEMENT_VERSION),
    Buffer.from(normalizeHex(input.logId), 'hex'),
    uint(input.sequence),
    uint(input.periodStart),
    uint(input.periodEnd),
    Buffer.from(normalizeHex(input.combinedRoot), 'hex'),
    Buffer.from(
      input.previousCombinedRoot ? normalizeHex(input.previousCombinedRoot) : ZERO,
      'hex',
    ),
    Buffer.from(normalizeHex(input.signingKeyFingerprint), 'hex'),
  ]);
}

export function statementFingerprint(statement: string | Uint8Array): Hex {
  return sha256Hex(typeof statement === 'string' ? hexToBytes(statement) : statement);
}

/** `SHA-256("unifyid-audit-log:" + name)`: which log (production, staging, local) a statement belongs to. */
export function logIdFor(name: string): Hex {
  return sha256Hex(`unifyid-audit-log:${name}`);
}

/** `SHA-256(0x04 || X || Y)`: a P-256 key's on-chain identity. */
export function signingKeyFingerprint(key: Pick<PublishedKey, 'x' | 'y'>): Hex {
  const x = Buffer.from(key.x, 'base64url');
  const y = Buffer.from(key.y, 'base64url');
  if (x.length !== 32 || y.length !== 32)
    throw new TypeError('A P-256 key has 32-byte coordinates.');
  return sha256Hex(Buffer.concat([Buffer.from([0x04]), x, y]));
}

/**
 * `SHA-256(0x02 || H(audit) || ... || H(transparency))` with
 * `H(s) = uint8(len(name)) || name || uint64_be(treeSize) || rootHash`.
 * Every stream must be present exactly once; order is fixed, not taken from the input.
 */
export function combinedRoot(heads: readonly StreamHead[]): Hex {
  const parts: Buffer[] = [Buffer.from([0x02])];
  for (const stream of SEALED_STREAMS) {
    const matching = heads.filter((head) => head.stream === stream);
    if (matching.length !== 1)
      throw new TypeError(`The stream heads must name ${stream} exactly once.`);
    const head = matching[0]!;
    const size = BigInt(head.treeSize);
    if (size < 0n || size >> 64n !== 0n)
      throw new TypeError(`Tree size for ${stream} is out of range.`);
    if (size === 0n && !safeEqual(head.rootHash, EMPTY_TREE_HASH))
      throw new TypeError(`An empty ${stream} tree has the empty root.`);
    const name = Buffer.from(stream, 'ascii');
    const sizeBytes = Buffer.alloc(8);
    sizeBytes.writeBigUInt64BE(size);
    parts.push(
      Buffer.from([name.length]),
      name,
      sizeBytes,
      Buffer.from(normalizeHex(head.rootHash), 'hex'),
    );
  }
  if (heads.length !== SEALED_STREAMS.length) throw new TypeError('Unexpected stream heads.');
  return sha256Hex(Buffer.concat(parts));
}
