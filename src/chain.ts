import {
  createPublicClient,
  decodeEventLog,
  http,
  type Hex as ViemHex,
  type PublicClient,
} from 'viem';
import { normalizeHex, safeEqual, type Hex } from './merkle.js';
import { Checks } from './audit-proof.js';
import type { DecodedStatement } from './statement.js';

/**
 * The chain checks. Everything is read through an RPC URL the person chooses;
 * nothing here calls UnifyID.
 *
 * 1. UnifyID's anchor contract is the authority: it only accepts a statement
 *    signed by a key the multisig registered, from an authorised submitter, in
 *    unbroken sequence. The verifier asks it which sequence holds the
 *    fingerprint and what it stored there, and (when a transaction is named)
 *    finds the `CheckpointAnchored` event in that transaction.
 * 2. Sign Protocol is the second witness: the UnifyID hook records which
 *    attestation carries the fingerprint, and the attestation's data must be
 *    the very same statement and signature, attested by an authorised submitter.
 */

export const UNIFYID_ANCHOR_ABI = [
  {
    type: 'function',
    name: 'logId',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'bytes32' }],
  },
  {
    type: 'function',
    name: 'latestSequence',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'uint64' }],
  },
  {
    type: 'function',
    name: 'sequenceOf',
    stateMutability: 'view',
    inputs: [{ name: 'fingerprint', type: 'bytes32' }],
    outputs: [{ type: 'uint64' }],
  },
  {
    type: 'function',
    name: 'checkpoint',
    stateMutability: 'view',
    inputs: [{ name: 'sequence', type: 'uint64' }],
    outputs: [
      {
        type: 'tuple',
        components: [
          { name: 'fingerprint', type: 'bytes32' },
          { name: 'combinedRoot', type: 'bytes32' },
          { name: 'periodEnd', type: 'uint64' },
          { name: 'anchoredAt', type: 'uint64' },
          { name: 'blockNumber', type: 'uint64' },
        ],
      },
    ],
  },
  {
    type: 'function',
    name: 'isSubmitter',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ type: 'bool' }],
  },
  {
    type: 'event',
    name: 'CheckpointAnchored',
    inputs: [
      { name: 'sequence', type: 'uint64', indexed: true },
      { name: 'fingerprint', type: 'bytes32', indexed: true },
      { name: 'combinedRoot', type: 'bytes32', indexed: true },
      { name: 'previousCombinedRoot', type: 'bytes32', indexed: false },
      { name: 'keyFingerprint', type: 'bytes32', indexed: false },
      { name: 'submitter', type: 'address', indexed: false },
      { name: 'statement', type: 'bytes', indexed: false },
      { name: 'signature', type: 'bytes', indexed: false },
    ],
  },
] as const;

export const UNIFYID_SIGN_HOOK_ABI = [
  {
    type: 'function',
    name: 'attestationOf',
    stateMutability: 'view',
    inputs: [{ name: 'fingerprint', type: 'bytes32' }],
    outputs: [
      { name: 'attestationId', type: 'uint64' },
      { name: 'sequence', type: 'uint64' },
    ],
  },
  {
    type: 'function',
    name: 'anchorContract',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'address' }],
  },
  {
    type: 'function',
    name: 'fingerprintAt',
    stateMutability: 'view',
    inputs: [{ name: 'sequence', type: 'uint64' }],
    outputs: [{ type: 'bytes32' }],
  },
] as const;

/** Sign Protocol's `getAttestation(uint64)` and `getSchema(uint64)` (ISP, MIT interface). */
export const SIGN_PROTOCOL_ABI = [
  {
    type: 'function',
    name: 'getSchema',
    stateMutability: 'view',
    inputs: [{ name: 'schemaId', type: 'uint64' }],
    outputs: [
      {
        type: 'tuple',
        components: [
          { name: 'registrant', type: 'address' },
          { name: 'revocable', type: 'bool' },
          { name: 'dataLocation', type: 'uint8' },
          { name: 'maxValidFor', type: 'uint64' },
          { name: 'hook', type: 'address' },
          { name: 'timestamp', type: 'uint64' },
          { name: 'data', type: 'string' },
        ],
      },
    ],
  },
  {
    type: 'function',
    name: 'getAttestation',
    stateMutability: 'view',
    inputs: [{ name: 'attestationId', type: 'uint64' }],
    outputs: [
      {
        type: 'tuple',
        components: [
          { name: 'schemaId', type: 'uint64' },
          { name: 'linkedAttestationId', type: 'uint64' },
          { name: 'attestTimestamp', type: 'uint64' },
          { name: 'revokeTimestamp', type: 'uint64' },
          { name: 'attester', type: 'address' },
          { name: 'validUntil', type: 'uint64' },
          { name: 'dataLocation', type: 'uint8' },
          { name: 'revoked', type: 'bool' },
          { name: 'recipients', type: 'bytes[]' },
          { name: 'data', type: 'bytes' },
        ],
      },
    ],
  },
] as const;

export interface ContractAnchorRef {
  chainId: string;
  contractAddress: string;
  sequence?: string | null;
  transactionHash?: string | null;
  blockNumber?: string | null;
}

export interface SignAnchorRef {
  chainId: string;
  signProtocolAddress: string;
  hookAddress: string;
  anchorContractAddress?: string | null;
  schemaId?: string | null;
  attestationId?: string | null;
  transactionHash?: string | null;
  blockNumber?: string | null;
}

export interface ChainOptions {
  /** The RPC URL the person trusts for UnifyID's contract: their own node, or a provider they choose. */
  rpcUrl: string;
  /** For Sign Protocol, when it is read through another endpoint; defaults to `rpcUrl`. */
  signRpcUrl?: string;
  /** Blocks on top of the anchoring block before an anchor counts as final. Default 1. */
  minConfirmations?: number;
  /** A client to use instead of creating one (tests). */
  client?: PublicClient;
  signClient?: PublicClient;
}

export interface CheckpointFacts {
  statement: DecodedStatement;
  statementHex: string;
  signatureHex: string;
  fingerprint: Hex;
}

const bytes32 = (hash: Hex) => `0x${normalizeHex(hash)}` as ViemHex;
const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

function clientFor(url: string): PublicClient {
  return createPublicClient({
    transport: http(url, { retryCount: 1, timeout: 15_000 }),
  }) as PublicClient;
}

/** Check 8: the checkpoint is anchored on UnifyID's contract, identically. */
export async function verifyOnContract(
  facts: CheckpointFacts,
  ref: ContractAnchorRef,
  options: ChainOptions,
  checks: Checks,
): Promise<{ anchored: boolean; submitter: string | null }> {
  const client = options.client ?? clientFor(options.rpcUrl);
  const address = ref.contractAddress as ViemHex;
  try {
    const chainId = await client.getChainId();
    if (String(chainId) !== String(ref.chainId)) {
      checks.fail(
        'unifyid_contract',
        `The RPC URL serves chain ${chainId}, but the anchor is on chain ${ref.chainId}.`,
      );
      return { anchored: false, submitter: null };
    }
    const logId = await client.readContract({
      address,
      abi: UNIFYID_ANCHOR_ABI,
      functionName: 'logId',
    });
    if (!safeEqual(logId, facts.statement.logId)) {
      checks.fail(
        'unifyid_contract',
        `Contract ${address} anchors a different log (${logId}); it is not the contract for this checkpoint.`,
      );
      return { anchored: false, submitter: null };
    }
    const sequence = await client.readContract({
      address,
      abi: UNIFYID_ANCHOR_ABI,
      functionName: 'sequenceOf',
      args: [bytes32(facts.fingerprint)],
    });
    if (sequence === 0n) {
      const stored = await storedAt(client, address, BigInt(facts.statement.sequence));
      if (stored && !/^0x0{64}$/i.test(stored.fingerprint)) {
        checks.fail(
          'unifyid_contract',
          `Forged checkpoint: UnifyID's contract holds fingerprint ${normalizeHex(stored.fingerprint)} at sequence ${facts.statement.sequence}, not ${facts.fingerprint}.`,
        );
        return { anchored: false, submitter: null };
      }
      checks.unavailable(
        'unifyid_contract',
        `Checkpoint ${facts.statement.sequence} is not on UnifyID's contract yet.`,
      );
      return { anchored: false, submitter: null };
    }
    if (sequence.toString() !== facts.statement.sequence) {
      checks.fail(
        'unifyid_contract',
        `UnifyID's contract holds this fingerprint at sequence ${sequence}, not ${facts.statement.sequence}.`,
      );
      return { anchored: false, submitter: null };
    }
    const stored = await storedAt(client, address, sequence);
    if (
      !stored ||
      !safeEqual(stored.fingerprint, facts.fingerprint) ||
      !safeEqual(stored.combinedRoot, facts.statement.combinedRoot) ||
      stored.periodEnd.toString() !== facts.statement.periodEnd
    ) {
      checks.fail(
        'unifyid_contract',
        `UnifyID's contract stores a different checkpoint at sequence ${sequence}.`,
      );
      return { anchored: false, submitter: null };
    }
    const head = await client.getBlockNumber();
    const confirmations = stored.blockNumber > 0n ? head - stored.blockNumber + 1n : 0n;
    const needed = BigInt(options.minConfirmations ?? 1);
    let submitter: string | null = null;
    let transaction = '';
    if (ref.transactionHash) {
      const receipt = await client.getTransactionReceipt({ hash: ref.transactionHash as ViemHex });
      const event = receipt.logs
        .filter((log) => same(log.address, address))
        .map((log) => {
          try {
            return decodeEventLog({ abi: UNIFYID_ANCHOR_ABI, data: log.data, topics: log.topics });
          } catch {
            return null;
          }
        })
        .find(
          (decoded) =>
            decoded?.eventName === 'CheckpointAnchored' &&
            safeEqual(decoded.args.fingerprint, facts.fingerprint),
        );
      if (receipt.status !== 'success' || !event || event.eventName !== 'CheckpointAnchored') {
        checks.fail(
          'unifyid_contract',
          `Transaction ${ref.transactionHash} did not anchor this checkpoint on ${address}.`,
        );
        return { anchored: false, submitter: null };
      }
      if (
        !same(event.args.statement, facts.statementHex) ||
        !same(event.args.signature, facts.signatureHex) ||
        !safeEqual(event.args.keyFingerprint, facts.statement.signingKeyFingerprint)
      ) {
        checks.fail(
          'unifyid_contract',
          `Transaction ${ref.transactionHash} anchored different statement bytes.`,
        );
        return { anchored: false, submitter: null };
      }
      submitter = event.args.submitter;
      transaction = ` in transaction ${ref.transactionHash} (block ${receipt.blockNumber})`;
    }
    if (confirmations < needed) {
      checks.unavailable(
        'unifyid_contract',
        `Checkpoint ${sequence} is on UnifyID's contract${transaction} but has ${confirmations} of ${needed} confirmations.`,
      );
      return { anchored: false, submitter };
    }
    checks.pass(
      'unifyid_contract',
      `UnifyID's contract ${address} on chain ${ref.chainId} holds checkpoint ${sequence} with this fingerprint and root${transaction}; ${confirmations} confirmations. The contract checked the signature against its registered keys, and the continuity, when it accepted it.`,
    );
    return { anchored: true, submitter };
  } catch (error) {
    checks.unavailable(
      'unifyid_contract',
      `The chain could not be read through the RPC URL: ${short(error)}`,
    );
    return { anchored: false, submitter: null };
  }
}

async function storedAt(client: PublicClient, address: ViemHex, sequence: bigint) {
  const stored = await client.readContract({
    address,
    abi: UNIFYID_ANCHOR_ABI,
    functionName: 'checkpoint',
    args: [sequence],
  });
  return {
    fingerprint: stored.fingerprint,
    combinedRoot: stored.combinedRoot,
    periodEnd: BigInt(stored.periodEnd),
    blockNumber: BigInt(stored.blockNumber),
  };
}

/** Check 9: Sign Protocol carries the same statement and signature, attested by an authorised submitter. */
export async function verifyOnSignProtocol(
  facts: CheckpointFacts,
  ref: SignAnchorRef,
  contract: ContractAnchorRef | null,
  options: ChainOptions,
  checks: Checks,
): Promise<{ attested: boolean }> {
  const client =
    options.signClient ??
    (options.signRpcUrl
      ? clientFor(options.signRpcUrl)
      : (options.client ?? clientFor(options.rpcUrl)));
  try {
    const chainId = await client.getChainId();
    if (String(chainId) !== String(ref.chainId)) {
      checks.fail(
        'sign_protocol',
        `The Sign RPC URL serves chain ${chainId}, but the attestation is on chain ${ref.chainId}.`,
      );
      return { attested: false };
    }
    const hook = ref.hookAddress as ViemHex;
    const anchorAddress = (ref.anchorContractAddress ?? contract?.contractAddress) as
      ViemHex | undefined;
    if (anchorAddress) {
      const bound = await client.readContract({
        address: hook,
        abi: UNIFYID_SIGN_HOOK_ABI,
        functionName: 'anchorContract',
      });
      if (!same(bound, anchorAddress)) {
        checks.fail(
          'sign_protocol',
          `Hook ${hook} reads signers from ${bound}, not UnifyID's contract ${anchorAddress}; it is not UnifyID's hook.`,
        );
        return { attested: false };
      }
    }
    const [attestationId] = await client.readContract({
      address: hook,
      abi: UNIFYID_SIGN_HOOK_ABI,
      functionName: 'attestationOf',
      args: [bytes32(facts.fingerprint)],
    });
    if (attestationId === 0n) {
      const other = await client.readContract({
        address: hook,
        abi: UNIFYID_SIGN_HOOK_ABI,
        functionName: 'fingerprintAt',
        args: [BigInt(facts.statement.sequence)],
      });
      if (!/^0x0{64}$/i.test(other)) {
        checks.fail(
          'sign_protocol',
          `Split view: Sign Protocol holds fingerprint ${normalizeHex(other)} for checkpoint ${facts.statement.sequence}, not ${facts.fingerprint}.`,
        );
        return { attested: false };
      }
      checks.unavailable(
        'sign_protocol',
        `Checkpoint ${facts.statement.sequence} is not attested on Sign Protocol yet.`,
      );
      return { attested: false };
    }
    if (ref.attestationId && ref.attestationId !== attestationId.toString()) {
      checks.fail(
        'sign_protocol',
        `The hook names attestation ${attestationId}, not ${ref.attestationId}.`,
      );
      return { attested: false };
    }
    const attestation = await client.readContract({
      address: ref.signProtocolAddress as ViemHex,
      abi: SIGN_PROTOCOL_ABI,
      functionName: 'getAttestation',
      args: [attestationId],
    });
    if (
      ref.schemaId !== undefined &&
      ref.schemaId !== null &&
      attestation.schemaId.toString() !== String(ref.schemaId)
    ) {
      checks.fail(
        'sign_protocol',
        `Attestation ${attestationId} is under schema ${attestation.schemaId}, not UnifyID's schema ${ref.schemaId}.`,
      );
      return { attested: false };
    }
    const schema = await client.readContract({
      address: ref.signProtocolAddress as ViemHex,
      abi: SIGN_PROTOCOL_ABI,
      functionName: 'getSchema',
      args: [attestation.schemaId],
    });
    if (!same(schema.hook, hook)) {
      checks.fail(
        'sign_protocol',
        `Attestation ${attestationId}'s schema is not guarded by UnifyID's hook ${hook}.`,
      );
      return { attested: false };
    }
    if (attestation.revoked) {
      checks.fail('sign_protocol', `Attestation ${attestationId} has been revoked.`);
      return { attested: false };
    }
    const decoded = decodeAttestationData(attestation.data);
    if (!decoded) {
      checks.fail(
        'sign_protocol',
        `Attestation ${attestationId} does not hold a UnifyID checkpoint in the schema's layout.`,
      );
      return { attested: false };
    }
    const { statement, signature } = decoded;
    if (!same(statement, facts.statementHex) || !same(signature, facts.signatureHex)) {
      checks.fail(
        'sign_protocol',
        `Split view: Sign Protocol attestation ${attestationId} carries different statement bytes from UnifyID's checkpoint.`,
      );
      return { attested: false };
    }
    // The hook refused any attester UnifyID's contract did not authorise at the time; a wallet
    // removed since then is reported, not failed, because the statement's signature already proves its origin.
    let attester = `attested by ${attestation.attester}`;
    if (anchorAddress) {
      const allowed = await (options.client ?? client).readContract({
        address: anchorAddress,
        abi: UNIFYID_ANCHOR_ABI,
        functionName: 'isSubmitter',
        args: [attestation.attester],
      });
      attester = allowed
        ? `attested by authorised submitter ${attestation.attester}`
        : `attested by ${attestation.attester}, which is no longer an authorised submitter`;
    }
    checks.pass(
      'sign_protocol',
      `Second witness: Sign Protocol attestation ${attestationId} on chain ${ref.chainId} carries the identical statement and signature, ${attester}.`,
    );
    return { attested: true };
  } catch (error) {
    checks.unavailable(
      'sign_protocol',
      `Sign Protocol could not be read through the RPC URL: ${short(error)}`,
    );
    return { attested: false };
  }
}

/**
 * UnifyID's Sign Protocol schema data: the ABI encoding of the statement's eight
 * static fields followed by `bytes signature`, exactly 384 bytes. The first 256
 * bytes are therefore the statement itself, word 8 is the signature's offset
 * (0x120), word 9 its length (64) and the last 64 bytes the signature.
 */
export function decodeAttestationData(
  data: string,
): { statement: string; signature: string } | null {
  const hex = data.toLowerCase().replace(/^0x/, '');
  if (hex.length !== 768 || !/^[0-9a-f]*$/.test(hex)) return null;
  const word = (index: number) => BigInt(`0x${hex.slice(index * 64, (index + 1) * 64)}`);
  if (word(8) !== 0x120n || word(9) !== 64n) return null;
  return { statement: `0x${hex.slice(0, 512)}`, signature: `0x${hex.slice(640, 768)}` };
}

function short(error: unknown): string {
  const text =
    error instanceof Error
      ? ((error as { shortMessage?: string }).shortMessage ?? error.message)
      : String(error);
  return text.split('\n')[0]!.slice(0, 300);
}
