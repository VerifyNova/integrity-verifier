import { createHash, generateKeyPairSync, sign as signBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalJsonV1,
  combinedRoot,
  consistencyProof,
  EMPTY_TREE_HASH,
  encodeStatement,
  inclusionPath,
  leafHash,
  logIdFor,
  merkleTreeHash,
  parseKeySet,
  saltedLeafHash,
  SEALED_STREAMS,
  signingKeyFingerprint,
  statementFingerprint,
  toLowS,
  verifyCheckpointAnchors,
  verifyConsistency,
  verifyConsistencyProof,
  verifyInclusion,
  verifyProofBundle,
  type CheckpointView,
  type InclusionProof,
  type KeySet,
  type ProofBundle,
  type PublishedKey,
} from '../src/index.js';

/**
 * P8 T4: the open-source verifier, off-chain. Merkle arithmetic against RFC 6962
 * by construction, the 256-byte statement, the combined root, the signature
 * under published keys, and the refusals: a tampered record, a wrong key, a
 * forged checkpoint. The chain checks are in chain.test.ts and, through the
 * command line on Base mainnet's chain id, in cli.test.ts; UnifyID's API also
 * runs the CLI against a local Hardhat chain in its own integration suites.
 */

const sha = (value: Buffer | string) => createHash('sha256').update(value).digest('hex');
const hex32 = (seed: string) => sha(seed);

function key(): {
  jwk: PublishedKey;
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
} {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const kid = `audit-${createHash('sha256')
    .update(JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y }))
    .digest('base64url')
    .slice(0, 20)}`;
  return {
    jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid, alg: 'ES256', use: 'sig' },
    privateKey: pair.privateKey,
  };
}

interface Fixture {
  bundle: ProofBundle;
  keys: KeySet;
  record: Record<string, unknown>;
  signer: ReturnType<typeof key>;
}

/** A disclosure record sealed at index 2 of a 7-leaf tree, in checkpoint 3. */
function fixture(): Fixture {
  const signer = key();
  const record = {
    schemaVersion: 2,
    stream: 'disclosure',
    eventType: 'personal_data.released',
    occurredAt: '2026-09-17T10:00:00.000Z',
    payload: { fieldsReleased: ['email'], channel: 'userinfo' },
    subjects: [{ type: 'person', id: 'person-1', role: 'subject' }],
  };
  const contentHash = sha(canonicalJsonV1(record));
  const leafSalt = hex32('salt');
  const leaves = Array.from({ length: 7 }, (_, index) =>
    index === 2 ? saltedLeafHash(leafSalt, contentHash) : leafHash(`other-${index}`),
  );
  const rootHash = merkleTreeHash(leaves);
  const heads = SEALED_STREAMS.map((stream) =>
    stream === 'disclosure'
      ? { stream, treeSize: '7', rootHash }
      : stream === 'audit'
        ? {
            stream,
            treeSize: '3',
            rootHash: merkleTreeHash([leafHash('a'), leafHash('b'), leafHash('c')]),
          }
        : { stream, treeSize: '0', rootHash: EMPTY_TREE_HASH },
  );
  const root = combinedRoot(heads);
  const statement = encodeStatement({
    logId: logIdFor('unifyid-local'),
    sequence: '3',
    periodStart: String(Date.parse('2026-09-17T09:00:00.000Z') / 1000),
    periodEnd: String(Date.parse('2026-09-17T10:05:00.000Z') / 1000),
    combinedRoot: root,
    previousCombinedRoot: hex32('previous'),
    signingKeyFingerprint: signingKeyFingerprint(signer.jwk),
  });
  const signature = toLowS(
    signBytes('sha256', statement, { key: signer.privateKey, dsaEncoding: 'ieee-p1363' }),
  );
  const checkpoint: CheckpointView = {
    checkpointId: '00000000-0000-4000-8000-000000000003',
    sequence: '3',
    version: 1,
    logId: logIdFor('unifyid-local'),
    periodStart: '2026-09-17T09:00:00.000Z',
    periodEnd: '2026-09-17T10:05:00.000Z',
    combinedRoot: root,
    previousCombinedRoot: hex32('previous'),
    fingerprint: statementFingerprint(statement),
    previousFingerprint: hex32('previous-fingerprint'),
    statement: `0x${statement.toString('hex')}`,
    signature: `0x${signature.toString('hex')}`,
    signingKeyId: signer.jwk.kid,
    signingKeyFingerprint: signingKeyFingerprint(signer.jwk),
  };
  const proof: InclusionProof = {
    format: 'unifyid.audit.inclusion-proof',
    version: 1,
    stream: 'disclosure',
    eventId: '11111111-1111-4111-8111-111111111111',
    sequence: '3',
    leafIndex: '2',
    leaf: { state: 'present', leafSalt, contentHash, leafHash: leaves[2]! },
    treeSize: '7',
    rootHash,
    auditPath: inclusionPath(2, leaves),
    streamHeads: heads,
    checkpoint,
    envelope: { canonicalization: 'unifyid-canonical-json-v1', schemaVersion: 2, value: record },
  };
  const bundle: ProofBundle = {
    format: 'unifyid.proof-bundle',
    version: 1,
    generatedAt: '2026-09-17T11:00:00.000Z',
    subject: {
      kind: 'ledger_entry',
      id: proof.eventId!,
      eventId: proof.eventId!,
      stream: 'disclosure',
      occurredAt: record.occurredAt,
      description: 'Your email was released',
    },
    state: 'sealed',
    recordWithheld: null,
    proof,
    anchors: { unifyid_contract: null, sign_protocol: null },
    keysUrl: null,
    howToVerify: 'unifyid-integrity-verify proof bundle.json --keys keys.json',
  };
  return { bundle, keys: { keys: [signer.jwk] }, record, signer };
}

describe('P8 T4 verifier: RFC 6962 Merkle arithmetic', () => {
  it('verifies every inclusion proof in trees of 1 to 33 leaves and refuses a moved leaf', () => {
    for (let size = 1; size <= 33; size += 1) {
      const leaves = Array.from({ length: size }, (_, index) => leafHash(`leaf-${index}`));
      const root = merkleTreeHash(leaves);
      for (let index = 0; index < size; index += 1) {
        const path = inclusionPath(index, leaves);
        expect(
          verifyInclusion({ leafHash: leaves[index]!, index, treeSize: size, path, root }),
        ).toBe(true);
        if (size > 1)
          expect(
            verifyInclusion({
              leafHash: leaves[index]!,
              index: (index + 1) % size,
              treeSize: size,
              path,
              root,
            }),
          ).toBe(false);
      }
    }
  });

  it('verifies consistency between every pair of sizes up to 20 and refuses a rewritten prefix', () => {
    const leaves = Array.from({ length: 20 }, (_, index) => leafHash(`leaf-${index}`));
    for (let second = 1; second <= 20; second += 1)
      for (let first = 1; first <= second; first += 1) {
        const proof = consistencyProof(first, leaves.slice(0, second));
        const firstRoot = merkleTreeHash(leaves.slice(0, first));
        const secondRoot = merkleTreeHash(leaves.slice(0, second));
        expect(
          verifyConsistency({ firstSize: first, secondSize: second, firstRoot, secondRoot, proof }),
        ).toBe(true);
        if (first < second) {
          const rewritten = [...leaves.slice(0, second)];
          rewritten[0] = leafHash('rewritten');
          expect(
            verifyConsistency({
              firstSize: first,
              secondSize: second,
              firstRoot,
              secondRoot: merkleTreeHash(rewritten),
              proof,
            }),
          ).toBe(false);
        }
      }
  });

  it('uses the RFC 6962 empty root and domain-separated leaf and node hashes', () => {
    expect(EMPTY_TREE_HASH).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(leafHash('')).toBe(sha(Buffer.from([0])));
    const two = [leafHash('a'), leafHash('b')];
    expect(merkleTreeHash(two)).toBe(
      sha(
        Buffer.concat([Buffer.from([1]), Buffer.from(two[0]!, 'hex'), Buffer.from(two[1]!, 'hex')]),
      ),
    );
  });
});

describe('P8 T4 verifier: a sealed record, off-chain', () => {
  it('verifies the record, leaf, inclusion, combined root, statement and signature', async () => {
    const { bundle, keys } = fixture();
    const report = await verifyProofBundle(bundle, { keys });
    expect(report.outcome).toBe('verified_off_chain');
    expect(report.valid).toBe(true);
    expect(
      report.checks.filter((check) => check.status === 'passed').map((check) => check.check),
    ).toEqual([
      'record',
      'leaf',
      'inclusion',
      'stream_head',
      'combined_root',
      'statement',
      'signing_key',
      'signature',
    ]);
  });

  it('refuses a tampered record, in the bundle or supplied from an export', async () => {
    const { bundle, keys, record } = fixture();
    const edited = structuredClone(bundle);
    (
      edited.proof!.envelope!.value as { payload: { fieldsReleased: string[] } }
    ).payload.fieldsReleased = ['email', 'phone_number'];
    const one = await verifyProofBundle(edited, { keys });
    expect(one).toMatchObject({ outcome: 'invalid', valid: false });
    expect(one.checks.at(-1)).toMatchObject({ check: 'record', status: 'failed' });

    const two = await verifyProofBundle(bundle, {
      keys,
      record: { ...record, eventType: 'personal_data.viewed' },
    });
    expect(two.outcome).toBe('invalid');
  });

  it('refuses a changed salt, a changed path and a stream head that is not the proven tree', async () => {
    const { bundle, keys } = fixture();
    const salt = structuredClone(bundle);
    salt.proof!.leaf.leafSalt = hex32('guess');
    expect((await verifyProofBundle(salt, { keys })).checks.at(-1)).toMatchObject({
      check: 'leaf',
      status: 'failed',
    });
    const path = structuredClone(bundle);
    path.proof!.auditPath[0] = hex32('forged');
    expect((await verifyProofBundle(path, { keys })).checks.at(-1)).toMatchObject({
      check: 'inclusion',
      status: 'failed',
    });
    const head = structuredClone(bundle);
    head.proof!.streamHeads = head.proof!.streamHeads.map((row) =>
      row.stream === 'disclosure' ? { ...row, treeSize: '8' } : row,
    );
    expect((await verifyProofBundle(head, { keys })).checks.at(-1)).toMatchObject({
      check: 'stream_head',
      status: 'failed',
    });
  });

  it('refuses a wrong key: an unknown key id, and a published key that did not sign', async () => {
    const { bundle } = fixture();
    const stranger = key();
    const unknown = await verifyProofBundle(bundle, { keys: { keys: [stranger.jwk] } });
    expect(unknown.outcome).toBe('invalid');
    expect(unknown.checks.at(-1)).toMatchObject({ check: 'signing_key', status: 'failed' });

    // A key set that claims the signer's kid and fingerprint cannot, because the fingerprint is of X and Y.
    const impostor = await verifyProofBundle(bundle, {
      keys: { keys: [{ ...stranger.jwk, kid: bundle.proof!.checkpoint.signingKeyId }] },
    });
    expect(impostor.outcome).toBe('invalid');
    expect(impostor.checks.at(-1)).toMatchObject({ check: 'signing_key', status: 'failed' });
  });

  it('refuses a forged checkpoint: a statement re-signed by another key, a changed root, a mismatched view', async () => {
    const fx = fixture();
    const attacker = key();
    // The attacker rewrites the record, rebuilds the tree and signs a statement naming their own key.
    const forged = structuredClone(fx.bundle);
    const statement = Buffer.from(forged.proof!.checkpoint.statement.slice(2), 'hex');
    const rewrittenKey = Buffer.from(signingKeyFingerprint(attacker.jwk), 'hex');
    rewrittenKey.copy(statement, 224);
    const signature = toLowS(
      signBytes('sha256', statement, { key: attacker.privateKey, dsaEncoding: 'ieee-p1363' }),
    );
    forged.proof!.checkpoint = {
      ...forged.proof!.checkpoint,
      statement: `0x${statement.toString('hex')}`,
      signature: `0x${signature.toString('hex')}`,
      fingerprint: statementFingerprint(statement),
      signingKeyId: attacker.jwk.kid,
      signingKeyFingerprint: signingKeyFingerprint(attacker.jwk),
    };
    const report = await verifyProofBundle(forged, { keys: fx.keys });
    expect(report.outcome).toBe('invalid');
    expect(report.checks.at(-1)).toMatchObject({ check: 'signing_key', status: 'failed' });

    const root = structuredClone(fx.bundle);
    root.proof!.checkpoint.combinedRoot = hex32('other');
    expect((await verifyProofBundle(root, { keys: fx.keys })).checks.at(-1)).toMatchObject({
      check: 'combined_root',
      status: 'failed',
    });

    const flipped = structuredClone(fx.bundle);
    const bytes = Buffer.from(flipped.proof!.checkpoint.signature.slice(2), 'hex');
    bytes[10] = bytes[10]! ^ 0xff;
    flipped.proof!.checkpoint.signature = `0x${bytes.toString('hex')}`;
    expect((await verifyProofBundle(flipped, { keys: fx.keys })).checks.at(-1)).toMatchObject({
      check: 'signature',
      status: 'failed',
    });

    const view = structuredClone(fx.bundle);
    view.proof!.checkpoint.sequence = '4';
    expect((await verifyProofBundle(view, { keys: fx.keys })).checks.at(-1)).toMatchObject({
      check: 'statement',
      status: 'failed',
    });
  });

  it('proves a tombstone leaf without content, and says the record was not checked', async () => {
    const { bundle, keys } = fixture();
    const tomb = structuredClone(bundle);
    tomb.proof!.leaf = {
      state: 'tombstone',
      leafSalt: null,
      contentHash: null,
      leafHash: bundle.proof!.leaf.leafHash,
    };
    tomb.proof!.envelope = null;
    const report = await verifyProofBundle(tomb, { keys });
    expect(report.outcome).toBe('verified_off_chain');
    expect(report.checks[0]).toMatchObject({ check: 'record', status: 'skipped' });
  });

  it('says a record that is not sealed yet has nothing to verify', async () => {
    const { bundle, keys } = fixture();
    const report = await verifyProofBundle({ ...bundle, state: 'recorded', proof: null }, { keys });
    expect(report).toMatchObject({ outcome: 'not_sealed', valid: false });
  });

  it('verifies a checkpoint on its own and parses a published key document', async () => {
    const { bundle, signer } = fixture();
    const keys = parseKeySet({
      data: {
        keys: [
          { ...signer.jwk, status: 'active' },
          { kty: 'RSA', kid: 'x' },
        ],
      },
    });
    expect(keys.keys).toHaveLength(1);
    const report = await verifyCheckpointAnchors(bundle.proof!.checkpoint, { keys });
    expect(report.outcome).toBe('verified_off_chain');
  });

  it('verifies a consistency proof between two checkpoints and refuses a rewritten stream', () => {
    const signer = key();
    const logId = logIdFor('unifyid-local');
    const leaves = Array.from({ length: 9 }, (_, index) => leafHash(`e-${index}`));
    const heads = (size: number) =>
      SEALED_STREAMS.map((stream) =>
        stream === 'audit'
          ? { stream, treeSize: String(size), rootHash: merkleTreeHash(leaves.slice(0, size)) }
          : { stream, treeSize: '0', rootHash: EMPTY_TREE_HASH },
      );
    const view = (sequence: number, size: number, previous: string | null): CheckpointView => {
      const root = combinedRoot(heads(size));
      const statement = encodeStatement({
        logId,
        sequence: String(sequence),
        periodStart: String(1_800_000_000 + sequence * 3600 - 3600),
        periodEnd: String(1_800_000_000 + sequence * 3600),
        combinedRoot: root,
        previousCombinedRoot: previous,
        signingKeyFingerprint: signingKeyFingerprint(signer.jwk),
      });
      return {
        checkpointId: `cp-${sequence}`,
        sequence: String(sequence),
        version: 1,
        logId,
        periodStart: new Date((1_800_000_000 + sequence * 3600 - 3600) * 1000).toISOString(),
        periodEnd: new Date((1_800_000_000 + sequence * 3600) * 1000).toISOString(),
        combinedRoot: root,
        previousCombinedRoot: previous,
        fingerprint: statementFingerprint(statement),
        previousFingerprint: null,
        statement: `0x${statement.toString('hex')}`,
        signature: `0x${toLowS(signBytes('sha256', statement, { key: signer.privateKey, dsaEncoding: 'ieee-p1363' })).toString('hex')}`,
        signingKeyId: signer.jwk.kid,
        signingKeyFingerprint: signingKeyFingerprint(signer.jwk),
      };
    };
    const from = view(1, 5, null);
    const to = view(2, 9, from.combinedRoot);
    const document = {
      format: 'unifyid.audit.consistency-proof' as const,
      version: 1 as const,
      from,
      to,
      streams: SEALED_STREAMS.map((stream) =>
        stream === 'audit'
          ? {
              stream,
              fromTreeSize: '5',
              fromRootHash: merkleTreeHash(leaves.slice(0, 5)),
              toTreeSize: '9',
              toRootHash: merkleTreeHash(leaves),
              proof: consistencyProof(5, leaves),
            }
          : {
              stream,
              fromTreeSize: '0',
              fromRootHash: EMPTY_TREE_HASH,
              toTreeSize: '0',
              toRootHash: EMPTY_TREE_HASH,
              proof: [],
            },
      ),
    };
    const keys = { keys: [signer.jwk] };
    expect(verifyConsistencyProof(document, keys).failed).toBe(false);
    const rewritten = structuredClone(document);
    rewritten.streams[0]!.proof = consistencyProof(5, [leafHash('rewritten'), ...leaves.slice(1)]);
    expect(verifyConsistencyProof(rewritten, keys).failed).toBe(true);
  });
});
