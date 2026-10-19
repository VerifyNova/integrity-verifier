import { createHash, generateKeyPairSync, sign as signBytes } from 'node:crypto';
import { encodeAbiParameters, encodeEventTopics, pad, toHex, type Hex as ViemHex } from 'viem';
import {
  combinedRoot,
  EMPTY_TREE_HASH,
  encodeStatement,
  logIdFor,
  SEALED_STREAMS,
  signingKeyFingerprint,
  statementFingerprint,
  toLowS,
  UNIFYID_ANCHOR_ABI,
  type CheckpointView,
  type PublishedKey,
} from '../src/index.js';

/**
 * A checkpoint and a chain that carries it, shared by the chain checks' tests (a stand-in viem
 * client) and the command line's (a stand-in JSON-RPC endpoint). The chain answers exactly as the
 * compiled ABIs shape the contract, the hook and Sign Protocol.
 */

export const CONTRACT = `0x${'11'.repeat(20)}` as ViemHex;
export const HOOK = `0x${'22'.repeat(20)}` as ViemHex;
export const SIGN = `0x${'33'.repeat(20)}` as ViemHex;
export const SUBMITTER = `0x${'44'.repeat(20)}` as ViemHex;
export const TX = `0x${'ab'.repeat(32)}` as ViemHex;
export const ZERO32 = `0x${'0'.repeat(64)}` as ViemHex;
/** Base Sepolia and Base mainnet. */
export const BASE_SEPOLIA = 84532;
export const BASE_MAINNET = 8453;

function signer() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const key: PublishedKey = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid: 'audit-test', alg: 'ES256', use: 'sig' };
  return { key, privateKey: pair.privateKey };
}

/** Checkpoint 41 of a log whose five streams are all empty: the smallest statement that signs. */
export function checkpoint() {
  const { key, privateKey } = signer();
  const heads = SEALED_STREAMS.map((stream) => ({ stream, treeSize: '0', rootHash: EMPTY_TREE_HASH }));
  const root = combinedRoot(heads);
  const previous = createHash('sha256').update('previous').digest('hex');
  const statement = encodeStatement({
    logId: logIdFor('unifyid-test'),
    sequence: '41',
    periodStart: '1700000000',
    periodEnd: '1700003600',
    combinedRoot: root,
    previousCombinedRoot: previous,
    signingKeyFingerprint: signingKeyFingerprint(key),
  });
  const signature = toLowS(signBytes('sha256', statement, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
  const view: CheckpointView = {
    checkpointId: '00000000-0000-4000-8000-000000000041',
    sequence: '41',
    version: 1,
    logId: logIdFor('unifyid-test'),
    periodStart: new Date(1700000000 * 1000).toISOString(),
    periodEnd: new Date(1700003600 * 1000).toISOString(),
    combinedRoot: root,
    previousCombinedRoot: previous,
    fingerprint: statementFingerprint(statement),
    previousFingerprint: null,
    statement: `0x${statement.toString('hex')}`,
    signature: `0x${signature.toString('hex')}`,
    signingKeyId: key.kid,
    signingKeyFingerprint: signingKeyFingerprint(key),
  };
  return { view, keys: { keys: [key] }, root, previous };
}

/** The attestation data exactly as the API's Sign publisher encodes it: statement, offset 0x120, length 64, signature. */
export function attestationData(statement: string, signature: string): ViemHex {
  return `${statement}${pad(toHex(0x120), { size: 32 }).slice(2)}${pad(toHex(64), { size: 32 }).slice(2)}${signature.slice(2)}` as ViemHex;
}

/** The `CheckpointAnchored` log the contract emits, encoded with the real ABI. */
export function anchoredLog(view: CheckpointView, overrides: { statement?: string } = {}) {
  const topics = encodeEventTopics({
    abi: UNIFYID_ANCHOR_ABI,
    eventName: 'CheckpointAnchored',
    args: {
      sequence: BigInt(view.sequence),
      fingerprint: `0x${view.fingerprint}` as ViemHex,
      combinedRoot: `0x${view.combinedRoot}` as ViemHex,
    },
  });
  const data = encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'address' }, { type: 'bytes' }, { type: 'bytes' }],
    [
      `0x${view.previousCombinedRoot}` as ViemHex,
      `0x${view.signingKeyFingerprint}` as ViemHex,
      SUBMITTER,
      (overrides.statement ?? view.statement) as ViemHex,
      view.signature as ViemHex,
    ],
  );
  return { address: CONTRACT, topics: topics as unknown as readonly ViemHex[], data };
}

export type World = {
  chainId?: number;
  logId?: string;
  /** fingerprint → sequence the contract holds it at (0 = not anchored). */
  sequenceOf?: Record<string, bigint>;
  /** sequence → what the contract stores there. */
  stored?: Record<string, { fingerprint: string; combinedRoot: string; periodEnd: bigint; blockNumber: bigint }>;
  head?: bigint;
  receipt?: { status: 'success' | 'reverted'; blockNumber: bigint; logs: Array<{ address: ViemHex; topics: readonly ViemHex[]; data: ViemHex }> };
  hookAnchor?: string;
  attestationOf?: Record<string, [bigint, bigint]>;
  fingerprintAt?: Record<string, string>;
  attestation?: { schemaId: bigint; attester: string; revoked: boolean; data: ViemHex };
  schemaHook?: string;
  isSubmitter?: boolean;
  fail?: boolean;
};

/** What the contract, the hook or Sign Protocol returns for a view call, as viem decodes it. */
export function answer(world: World, functionName: string, args: readonly unknown[] = []): unknown {
  const bytes32 = (hex: string) => (hex.startsWith('0x') ? hex : `0x${hex}`);
  switch (functionName) {
    case 'logId':
      return bytes32(world.logId ?? '');
    case 'sequenceOf':
      return world.sequenceOf?.[String(args[0]).toLowerCase()] ?? 0n;
    case 'checkpoint': {
      const row = world.stored?.[String(args[0])];
      return row
        ? { fingerprint: bytes32(row.fingerprint), combinedRoot: bytes32(row.combinedRoot), periodEnd: row.periodEnd, anchoredAt: 1700003700n, blockNumber: row.blockNumber }
        : { fingerprint: ZERO32, combinedRoot: ZERO32, periodEnd: 0n, anchoredAt: 0n, blockNumber: 0n };
    }
    case 'isSubmitter':
      return world.isSubmitter ?? true;
    case 'anchorContract':
      return world.hookAnchor ?? CONTRACT;
    case 'attestationOf':
      return world.attestationOf?.[String(args[0]).toLowerCase()] ?? [0n, 0n];
    case 'fingerprintAt':
      return bytes32(world.fingerprintAt?.[String(args[0])] ?? ZERO32);
    case 'getAttestation':
      return {
        schemaId: world.attestation?.schemaId ?? 7n,
        linkedAttestationId: 0n,
        attestTimestamp: 1700003700n,
        revokeTimestamp: 0n,
        attester: world.attestation?.attester ?? SUBMITTER,
        validUntil: 0n,
        dataLocation: 0,
        revoked: world.attestation?.revoked ?? false,
        recipients: [],
        data: world.attestation?.data ?? '0x',
      };
    case 'getSchema':
      return { registrant: SUBMITTER, revocable: false, dataLocation: 0, maxValidFor: 0n, hook: world.schemaHook ?? HOOK, timestamp: 1700000000n, data: '' };
    default:
      throw new Error(`unexpected call ${functionName}`);
  }
}

/** Both channels' anchors as the API puts them in a bundle or an anchored-checkpoint file. */
export function anchors(view: CheckpointView, chainId: number = BASE_SEPOLIA) {
  return {
    unifyid_contract: { channel: 'unifyid_contract' as const, status: 'anchored' as const, confirmations: 10, anchoredAt: null, explorerUrl: null, chainId: String(chainId), contractAddress: CONTRACT, sequence: view.sequence, transactionHash: TX, blockNumber: '100' },
    sign_protocol: { channel: 'sign_protocol' as const, status: 'anchored' as const, confirmations: 10, anchoredAt: null, explorerUrl: null, chainId: String(chainId), signProtocolAddress: SIGN, hookAddress: HOOK, anchorContractAddress: CONTRACT, schemaId: '7', attestationId: '5', transactionHash: null, blockNumber: null },
  };
}

/** A world in which the contract and Sign both carry the checkpoint, faithfully. */
export function anchoredWorld(view: CheckpointView): World {
  return {
    logId: view.logId,
    sequenceOf: { [`0x${view.fingerprint}`]: 41n },
    stored: { '41': { fingerprint: view.fingerprint, combinedRoot: view.combinedRoot, periodEnd: 1700003600n, blockNumber: 100n } },
    head: 110n,
    receipt: { status: 'success', blockNumber: 100n, logs: [anchoredLog(view)] },
    attestationOf: { [`0x${view.fingerprint}`]: [5n, 41n] },
    attestation: { schemaId: 7n, attester: SUBMITTER, revoked: false, data: attestationData(view.statement, view.signature) },
  };
}
