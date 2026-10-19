import {
  leafHash as rfc6962LeafHash,
  normalizeHex,
  safeEqual,
  verifyConsistency,
  verifyInclusion,
  isHash,
  type Hex,
} from './merkle.js';
import { findKey, isLowS, verifyEs256, type KeySet, type PublishedKey } from './keys.js';
import {
  combinedRoot,
  decodeStatement,
  hexToBytes,
  SEALED_STREAMS,
  sha256Hex,
  signingKeyFingerprint,
  statementFingerprint,
  type DecodedStatement,
  type StreamHead,
} from './statement.js';

/**
 * Off-chain verification of UnifyID audit proofs: a record's content hash, its
 * salted leaf, the RFC 6962 inclusion proof to its stream's root, the combined
 * root over every stream, the 256-byte checkpoint statement, and the ES256
 * signature under a published key. The chain checks live in `chain.ts`.
 *
 * Every function returns the checks it made, in order, so a person (or the CLI)
 * can see exactly what was proven and what was not.
 */

export interface CheckpointView {
  checkpointId: string;
  sequence: string;
  version: number;
  logId: Hex;
  periodStart: string;
  periodEnd: string;
  combinedRoot: Hex;
  previousCombinedRoot: Hex | null;
  fingerprint: Hex;
  previousFingerprint: Hex | null;
  statement: string;
  signature: string;
  signingKeyId: string;
  signingKeyFingerprint: Hex;
  createdAt?: string;
}

export interface InclusionProof {
  format: 'unifyid.audit.inclusion-proof';
  version: 1;
  stream: string;
  eventId: string | null;
  sequence: string;
  leafIndex: string;
  leaf: {
    state: 'present' | 'tombstone';
    leafSalt: Hex | null;
    contentHash: Hex | null;
    leafHash: Hex;
  };
  treeSize: string;
  rootHash: Hex;
  auditPath: Hex[];
  streamHeads: StreamHead[];
  checkpoint: CheckpointView;
  envelope: {
    /** `unifyid-canonical-json-v1` today; a later canonicalization would name itself here. */
    canonicalization: string;
    schemaVersion: number;
    value: unknown;
  } | null;
}

export interface ConsistencyProofDocument {
  format: 'unifyid.audit.consistency-proof';
  version: 1;
  from: CheckpointView;
  to: CheckpointView;
  streams: Array<{
    stream: string;
    fromTreeSize: string;
    fromRootHash: Hex;
    toTreeSize: string;
    toRootHash: Hex;
    proof: Hex[];
  }>;
}

export type CheckName =
  | 'record'
  | 'leaf'
  | 'inclusion'
  | 'stream_head'
  | 'combined_root'
  | 'statement'
  | 'signing_key'
  | 'signature'
  | 'consistency'
  | 'unifyid_contract'
  | 'sign_protocol';

export type CheckStatus = 'passed' | 'failed' | 'skipped' | 'unavailable';

export interface Check {
  check: CheckName;
  status: CheckStatus;
  detail: string;
}

export class Checks {
  readonly items: Check[] = [];
  pass(check: CheckName, detail: string) {
    this.items.push({ check, status: 'passed', detail });
  }
  fail(check: CheckName, detail: string) {
    this.items.push({ check, status: 'failed', detail });
  }
  skip(check: CheckName, detail: string) {
    this.items.push({ check, status: 'skipped', detail });
  }
  unavailable(check: CheckName, detail: string) {
    this.items.push({ check, status: 'unavailable', detail });
  }
  get failed(): boolean {
    return this.items.some((item) => item.status === 'failed');
  }
  first(status: CheckStatus): Check | undefined {
    return this.items.find((item) => item.status === status);
  }
}

/**
 * UnifyID's canonical JSON (`unifyid-canonical-json-v1`): object keys sorted by
 * UTF-16 code unit order, no whitespace, `undefined` dropped from objects and
 * written as null in arrays, -0 as 0. Input is already parsed JSON, so there
 * are no dates or bigints to normalise.
 */
export function canonicalJsonV1(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return Object.is(value, -0) ? 0 : value;
  if (Array.isArray(value)) return value.map((entry) => sortValue(entry));
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .filter((key) => record[key] !== undefined && typeof record[key] !== 'function')
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        .map((key) => [key, sortValue(record[key])]),
    );
  }
  return value;
}

/** `SHA-256(0x00 || leafSalt || contentHash)`, the salted RFC 6962 leaf. */
export function saltedLeafHash(leafSalt: Hex, contentHash: Hex): Hex {
  return rfc6962LeafHash(
    Buffer.concat([
      Buffer.from(normalizeHex(leafSalt), 'hex'),
      Buffer.from(normalizeHex(contentHash), 'hex'),
    ]),
  );
}

function seconds(iso: string): string | null {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? Math.floor(ms / 1000).toString() : null;
}

/**
 * The checkpoint on its own: the statement decodes, matches the view, hashes
 * to the fingerprint, names a published key, and carries that key's signature.
 * Returns the decoded statement and the key when those checks pass.
 */
export function verifyCheckpoint(
  checkpoint: CheckpointView,
  keys: KeySet,
  checks = new Checks(),
): { checks: Checks; statement: DecodedStatement | null; key: PublishedKey | null } {
  let decoded: DecodedStatement;
  try {
    decoded = decodeStatement(checkpoint.statement);
  } catch (error) {
    checks.fail('statement', `The checkpoint statement does not decode: ${message(error)}`);
    return { checks, statement: null, key: null };
  }
  const mismatches: string[] = [];
  const same = (a: string | null, b: string | null) =>
    a === null || b === null ? a === b : safeEqual(a, b);
  if (decoded.sequence !== String(checkpoint.sequence)) mismatches.push('sequence');
  if (decoded.version !== Number(checkpoint.version)) mismatches.push('version');
  if (!same(decoded.logId, checkpoint.logId)) mismatches.push('logId');
  if (!same(decoded.combinedRoot, checkpoint.combinedRoot)) mismatches.push('combinedRoot');
  if (!same(decoded.previousCombinedRoot, checkpoint.previousCombinedRoot ?? null))
    mismatches.push('previousCombinedRoot');
  if (!same(decoded.signingKeyFingerprint, checkpoint.signingKeyFingerprint))
    mismatches.push('signingKeyFingerprint');
  if (
    seconds(checkpoint.periodStart) !== decoded.periodStart &&
    !(decoded.periodStart === '0' && decoded.sequence === '1')
  )
    mismatches.push('periodStart');
  if (seconds(checkpoint.periodEnd) !== decoded.periodEnd) mismatches.push('periodEnd');
  let fingerprint: Hex;
  try {
    fingerprint = statementFingerprint(checkpoint.statement);
  } catch {
    checks.fail('statement', 'The checkpoint statement is not hex.');
    return { checks, statement: null, key: null };
  }
  if (!isHash(checkpoint.fingerprint) || !safeEqual(fingerprint, checkpoint.fingerprint))
    mismatches.push('fingerprint');
  if (mismatches.length) {
    checks.fail(
      'statement',
      `The signed statement does not match the checkpoint it came with (${mismatches.join(', ')}).`,
    );
    return { checks, statement: decoded, key: null };
  }
  checks.pass(
    'statement',
    `Checkpoint ${decoded.sequence}: the 256-byte statement decodes, matches, and hashes to fingerprint ${fingerprint}.`,
  );

  const key =
    findKey(keys, checkpoint.signingKeyId) ??
    keys.keys.find((candidate) => {
      try {
        return safeEqual(signingKeyFingerprint(candidate), decoded.signingKeyFingerprint);
      } catch {
        return false;
      }
    }) ??
    null;
  if (!key) {
    checks.fail(
      'signing_key',
      `No published key matches ${checkpoint.signingKeyId}; the checkpoint cannot be attributed to UnifyID.`,
    );
    return { checks, statement: decoded, key: null };
  }
  let keyFingerprint: Hex;
  try {
    keyFingerprint = signingKeyFingerprint(key);
  } catch {
    checks.fail('signing_key', `Published key ${key.kid} is not a valid P-256 key.`);
    return { checks, statement: decoded, key: null };
  }
  if (!safeEqual(keyFingerprint, decoded.signingKeyFingerprint)) {
    checks.fail(
      'signing_key',
      `Key ${key.kid} is not the key the statement names (${decoded.signingKeyFingerprint}).`,
    );
    return { checks, statement: decoded, key: null };
  }
  checks.pass(
    'signing_key',
    `The statement names published key ${key.kid} (fingerprint ${keyFingerprint}).`,
  );

  let signature: Buffer;
  try {
    signature = hexToBytes(checkpoint.signature);
  } catch {
    checks.fail('signature', 'The signature is not hex.');
    return { checks, statement: decoded, key };
  }
  if (signature.length === 64 && !isLowS(signature)) {
    checks.fail(
      'signature',
      'The signature is not in its canonical low-S form, so it is not the signature UnifyID published.',
    );
    return { checks, statement: decoded, key };
  }
  if (signature.length !== 64 || !verifyEs256(hexToBytes(checkpoint.statement), signature, key)) {
    checks.fail(
      'signature',
      `The signature does not verify under ${key.kid}: the checkpoint was not signed by that key.`,
    );
    return { checks, statement: decoded, key };
  }
  checks.pass('signature', `ES256 signature over the statement verifies under ${key.kid}.`);
  return { checks, statement: decoded, key };
}

/**
 * A sealed record: steps 1 to 7 of the proof, with an optional record supplied
 * separately (for example the entry from the person's own export) in place of
 * the envelope the proof carries.
 */
export function verifyInclusionProof(
  proof: InclusionProof,
  keys: KeySet,
  options: { record?: unknown; checks?: Checks } = {},
): { checks: Checks; statement: DecodedStatement | null } {
  const checks = options.checks ?? new Checks();
  if (!proof || proof.format !== 'unifyid.audit.inclusion-proof' || Number(proof.version) !== 1) {
    checks.fail(
      'record',
      'This is not a UnifyID inclusion proof (format unifyid.audit.inclusion-proof, version 1).',
    );
    return { checks, statement: null };
  }
  if (!(SEALED_STREAMS as readonly string[]).includes(proof.stream)) {
    checks.fail('record', `Stream ${proof.stream} is not a sealed stream.`);
    return { checks, statement: null };
  }

  // 1. The record hashes to the content hash.
  const leaf = proof.leaf;
  const record = options.record !== undefined ? options.record : proof.envelope?.value;
  if (leaf.state === 'tombstone') {
    checks.skip(
      'record',
      'The record was deleted under the retention schedule; its tombstone keeps the leaf provable, but there is no content left to check.',
    );
  } else if (record === undefined || record === null) {
    checks.skip(
      'record',
      'No record was supplied, so only the content hash is proven, not what it describes.',
    );
  } else if (!leaf.contentHash || !isHash(leaf.contentHash)) {
    checks.fail('record', 'The proof carries no content hash for a present record.');
    return { checks, statement: null };
  } else {
    const computed = sha256Hex(canonicalJsonV1(record));
    if (!safeEqual(computed, leaf.contentHash)) {
      checks.fail(
        'record',
        `The record does not hash to the sealed content hash (${computed} is not ${leaf.contentHash}): it has been altered.`,
      );
      return { checks, statement: null };
    }
    checks.pass('record', `The record hashes to the sealed content hash ${leaf.contentHash}.`);
  }

  // 2. The salted leaf.
  if (leaf.state === 'present') {
    if (
      !leaf.leafSalt ||
      !leaf.contentHash ||
      !isHash(leaf.leafSalt) ||
      !isHash(leaf.contentHash)
    ) {
      checks.fail('leaf', 'A present record needs its leaf salt and content hash.');
      return { checks, statement: null };
    }
    const computed = saltedLeafHash(leaf.leafSalt, leaf.contentHash);
    if (!isHash(leaf.leafHash) || !safeEqual(computed, leaf.leafHash)) {
      checks.fail('leaf', 'The leaf hash is not SHA-256(0x00 || salt || contentHash).');
      return { checks, statement: null };
    }
    checks.pass(
      'leaf',
      `Salted leaf ${computed} at index ${proof.leafIndex} of the ${proof.stream} stream.`,
    );
  } else if (!isHash(leaf.leafHash)) {
    checks.fail('leaf', 'A tombstone proof needs its leaf hash.');
    return { checks, statement: null };
  } else {
    checks.pass(
      'leaf',
      `Tombstone leaf ${normalizeHex(leaf.leafHash)} at index ${proof.leafIndex}.`,
    );
  }
  if (BigInt(proof.leafIndex) !== BigInt(proof.sequence) - 1n) {
    checks.fail('leaf', 'The leaf index must be the stream sequence minus one.');
    return { checks, statement: null };
  }

  // 3. RFC 9162 inclusion.
  if (
    !verifyInclusion({
      leafHash: leaf.leafHash,
      index: proof.leafIndex,
      treeSize: proof.treeSize,
      path: proof.auditPath ?? [],
      root: proof.rootHash,
    })
  ) {
    checks.fail(
      'inclusion',
      `The inclusion proof does not lead from the leaf to root ${proof.rootHash} of a ${proof.treeSize}-leaf tree.`,
    );
    return { checks, statement: null };
  }
  checks.pass(
    'inclusion',
    `RFC 6962 inclusion proof (${proof.auditPath.length} nodes) leads to the ${proof.stream} root ${proof.rootHash} over ${proof.treeSize} records.`,
  );

  // 4. The stream head.
  const head = (proof.streamHeads ?? []).find((candidate) => candidate.stream === proof.stream);
  if (
    !head ||
    BigInt(head.treeSize) !== BigInt(proof.treeSize) ||
    !safeEqual(head.rootHash, proof.rootHash)
  ) {
    checks.fail(
      'stream_head',
      `The checkpoint's ${proof.stream} head is not the tree the record was proven in.`,
    );
    return { checks, statement: null };
  }
  checks.pass('stream_head', `The checkpoint's ${proof.stream} head is that tree.`);

  // 5. The combined root.
  let combined: Hex;
  try {
    combined = combinedRoot(proof.streamHeads);
  } catch (error) {
    checks.fail('combined_root', `The stream heads are malformed: ${message(error)}`);
    return { checks, statement: null };
  }
  if (!safeEqual(combined, proof.checkpoint.combinedRoot)) {
    checks.fail(
      'combined_root',
      `The five stream heads combine to ${combined}, not the checkpoint's root ${proof.checkpoint.combinedRoot}.`,
    );
    return { checks, statement: null };
  }
  checks.pass('combined_root', `The five stream heads combine to the checkpoint root ${combined}.`);

  // 6 and 7. The statement and its signature.
  const { statement } = verifyCheckpoint(proof.checkpoint, keys, checks);
  return { checks, statement: checks.failed ? null : statement };
}

/** Two checkpoints: both verify, and every stream only grew between them. */
export function verifyConsistencyProof(proof: ConsistencyProofDocument, keys: KeySet): Checks {
  const checks = new Checks();
  const from = verifyCheckpoint(proof.from, keys, checks);
  if (checks.failed) return checks;
  verifyCheckpoint(proof.to, keys, checks);
  if (checks.failed || !from.statement) return checks;
  if (BigInt(proof.from.sequence) >= BigInt(proof.to.sequence)) {
    checks.fail('consistency', 'The first checkpoint must come before the second.');
    return checks;
  }
  const heads = (side: 'from' | 'to') =>
    proof.streams.map((row) => ({
      stream: row.stream,
      treeSize: side === 'from' ? row.fromTreeSize : row.toTreeSize,
      rootHash: side === 'from' ? row.fromRootHash : row.toRootHash,
    }));
  try {
    if (
      !safeEqual(combinedRoot(heads('from')), proof.from.combinedRoot) ||
      !safeEqual(combinedRoot(heads('to')), proof.to.combinedRoot)
    ) {
      checks.fail('consistency', 'The stream heads do not combine to the checkpoints’ roots.');
      return checks;
    }
  } catch (error) {
    checks.fail('consistency', `The stream heads are malformed: ${message(error)}`);
    return checks;
  }
  for (const row of proof.streams) {
    const ok = verifyConsistency({
      firstSize: row.fromTreeSize,
      secondSize: row.toTreeSize,
      firstRoot: row.fromRootHash,
      secondRoot: row.toRootHash,
      proof: row.proof,
    });
    if (!ok) {
      checks.fail(
        'consistency',
        `The ${row.stream} stream was rewritten between checkpoints ${proof.from.sequence} and ${proof.to.sequence}.`,
      );
      return checks;
    }
  }
  checks.pass(
    'consistency',
    `Between checkpoints ${proof.from.sequence} and ${proof.to.sequence} every stream only grew.`,
  );
  return checks;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
