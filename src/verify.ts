import {
  Checks,
  verifyCheckpoint,
  verifyInclusionProof,
  type Check,
  type CheckpointView,
  type InclusionProof,
} from './audit-proof.js';
import {
  verifyOnContract,
  verifyOnSignProtocol,
  type ChainOptions,
  type CheckpointFacts,
  type ContractAnchorRef,
  type SignAnchorRef,
} from './chain.js';
import type { KeySet } from './keys.js';
import type { DecodedStatement } from './statement.js';

/**
 * The proof bundle a person downloads from "See proof", and its verification
 * end to end: record, leaf, inclusion, combined root, statement, signature,
 * UnifyID's contract (the authority), then Sign Protocol (the second witness).
 */

export const PROOF_BUNDLE_FORMAT = 'unifyid.proof-bundle' as const;
export const PROOF_BUNDLE_SET_FORMAT = 'unifyid.proof-bundle-set' as const;

/**
 * - `recorded`: in the log, waiting for the next hourly checkpoint;
 * - `sealed`: in a signed checkpoint that no channel carries yet;
 * - `anchored_one_channel`: one channel carries the checkpoint (see `anchors`);
 * - `anchored_both`: UnifyID's contract and Sign Protocol both carry it.
 */
export type ProofState = 'recorded' | 'sealed' | 'anchored_one_channel' | 'anchored_both';

/** The channel states the API reports on a bundle (trust-anchoring `AnchorChannelStatus`). */
export type ChannelStatus =
  | 'pending'
  | 'submitting'
  | 'submitted'
  | 'confirming'
  | 'anchored'
  | 'failed'
  | 'retired';

export interface ContractChannel extends ContractAnchorRef {
  channel: 'unifyid_contract';
  status: ChannelStatus;
  confirmations: number;
  anchoredAt: string | null;
  explorerUrl: string | null;
}

export interface SignChannel extends SignAnchorRef {
  channel: 'sign_protocol';
  status: ChannelStatus;
  confirmations: number;
  anchoredAt: string | null;
  explorerUrl: string | null;
}

export interface ProofBundle {
  format: typeof PROOF_BUNDLE_FORMAT;
  version: 1;
  generatedAt: string;
  subject: {
    kind: 'ledger_entry' | 'agent_receipt' | 'audit_event' | 'transparency_fact';
    id: string;
    eventId: string;
    stream: string;
    occurredAt: string | null;
    /** A plain description of what the record is, for the person reading the file. */
    description: string | null;
  };
  state: ProofState;
  /** Why the record itself is not in the file, when it is not. */
  recordWithheld: string | null;
  /** Null while the record is not yet sealed. */
  proof: InclusionProof | null;
  anchors: {
    unifyid_contract: ContractChannel | null;
    sign_protocol: SignChannel | null;
  };
  /** Where UnifyID publishes its checkpoint keys; fetch them yourself, or use a copy you trust. */
  keysUrl: string | null;
  howToVerify: string;
}

export interface ProofBundleSet {
  format: typeof PROOF_BUNDLE_SET_FORMAT;
  version: 1;
  generatedAt: string;
  bundles: ProofBundle[];
}

export type Outcome =
  /** Every check passed, including UnifyID's contract. */
  | 'verified'
  /** Every off-chain check passed; no RPC URL was given, so nothing on chain was checked. */
  | 'verified_off_chain'
  /** The record and checkpoint verify, but UnifyID's contract does not hold the checkpoint yet. */
  | 'not_anchored'
  /** Not sealed yet: nothing to verify until the next hourly checkpoint. */
  | 'not_sealed'
  /** Something does not match: tampering, a wrong key, or a forged checkpoint. */
  | 'invalid'
  /** The chain could not be read. */
  | 'unavailable';

export interface VerificationReport {
  outcome: Outcome;
  valid: boolean;
  subject: ProofBundle['subject'] | null;
  checkpoint: { sequence: string; fingerprint: string } | null;
  authority: 'anchored' | 'not_anchored' | 'not_checked' | 'failed';
  witness: 'attested' | 'not_attested' | 'not_checked' | 'failed';
  checks: Check[];
  summary: string;
}

export interface VerifyOptions {
  keys: KeySet;
  /** Omit to verify off-chain only. */
  chain?: ChainOptions;
  /** A record from the person's own export, checked in place of the envelope in the bundle. */
  record?: unknown;
  /** Contract and Sign addresses the person trusts, overriding the ones the bundle names. */
  contract?: Partial<ContractAnchorRef>;
  sign?: Partial<SignAnchorRef>;
}

export function isProofBundle(value: unknown): value is ProofBundle {
  return (
    !!value && typeof value === 'object' && (value as ProofBundle).format === PROOF_BUNDLE_FORMAT
  );
}

export function isProofBundleSet(value: unknown): value is ProofBundleSet {
  return (
    !!value &&
    typeof value === 'object' &&
    (value as ProofBundleSet).format === PROOF_BUNDLE_SET_FORMAT
  );
}

export async function verifyProofBundle(
  bundle: ProofBundle,
  options: VerifyOptions,
): Promise<VerificationReport> {
  if (!isProofBundle(bundle) || Number(bundle.version) !== 1) {
    const checks = new Checks();
    checks.fail(
      'record',
      'This is not a UnifyID proof bundle (format unifyid.proof-bundle, version 1).',
    );
    return report('invalid', null, null, 'not_checked', 'not_checked', checks);
  }
  if (!bundle.proof) {
    const checks = new Checks();
    checks.skip(
      'inclusion',
      'The record is in the log but not yet in a checkpoint. Checkpoints are sealed hourly; download the proof again after the next one.',
    );
    return report('not_sealed', bundle.subject, null, 'not_checked', 'not_checked', checks);
  }
  const off = verifyInclusionProof(bundle.proof, options.keys, { record: options.record });
  if (
    bundle.proof.eventId &&
    bundle.subject?.eventId &&
    bundle.proof.eventId !== bundle.subject.eventId
  )
    off.checks.fail(
      'record',
      'The proof is for a different event from the one the bundle describes.',
    );
  return onChain(
    bundle.proof.checkpoint,
    off.statement,
    off.checks,
    bundle.subject,
    bundle.anchors,
    options,
  );
}

/** A checkpoint on its own (for example from the public transparency page): signature, contract, witness. */
export async function verifyCheckpointAnchors(
  checkpoint: CheckpointView & { anchors?: ProofBundle['anchors'] },
  options: VerifyOptions,
): Promise<VerificationReport> {
  const { checks, statement } = verifyCheckpoint(checkpoint, options.keys);
  return onChain(
    checkpoint,
    checks.failed ? null : statement,
    checks,
    null,
    checkpoint.anchors ?? { unifyid_contract: null, sign_protocol: null },
    options,
  );
}

async function onChain(
  checkpoint: CheckpointView,
  statement: DecodedStatement | null,
  checks: Checks,
  subject: ProofBundle['subject'] | null,
  anchors: ProofBundle['anchors'],
  options: VerifyOptions,
): Promise<VerificationReport> {
  const named = { sequence: String(checkpoint.sequence), fingerprint: checkpoint.fingerprint };
  if (checks.failed || !statement)
    return report('invalid', subject, named, 'not_checked', 'not_checked', checks);
  if (!options.chain) {
    checks.skip('unifyid_contract', 'No RPC URL was given, so the chain was not checked.');
    checks.skip('sign_protocol', 'No RPC URL was given, so the chain was not checked.');
    return report('verified_off_chain', subject, named, 'not_checked', 'not_checked', checks);
  }
  const facts: CheckpointFacts = {
    statement,
    statementHex: checkpoint.statement.toLowerCase(),
    signatureHex: checkpoint.signature.toLowerCase(),
    fingerprint: checkpoint.fingerprint,
  };
  const contractRef = mergeRef(anchors?.unifyid_contract ?? null, options.contract);
  let authority: VerificationReport['authority'] = 'not_anchored';
  if (!contractRef?.contractAddress || !contractRef.chainId) {
    checks.unavailable(
      'unifyid_contract',
      'No UnifyID contract address and chain id are known for this checkpoint: pass --contract and --chain-id, or wait until it is anchored.',
    );
  } else {
    const result = await verifyOnContract(
      facts,
      contractRef as ContractAnchorRef,
      options.chain,
      checks,
    );
    authority = result.anchored ? 'anchored' : checks.failed ? 'failed' : 'not_anchored';
  }
  if (checks.failed) return report('invalid', subject, named, authority, 'not_checked', checks);

  const signRef = mergeRef(anchors?.sign_protocol ?? null, options.sign);
  let witness: VerificationReport['witness'] = 'not_attested';
  if (!signRef?.hookAddress || !signRef.signProtocolAddress || !signRef.chainId) {
    checks.unavailable(
      'sign_protocol',
      'No Sign Protocol attestation is known for this checkpoint yet.',
    );
  } else {
    const result = await verifyOnSignProtocol(
      facts,
      signRef as SignAnchorRef,
      contractRef as ContractAnchorRef | null,
      options.chain,
      checks,
    );
    witness = result.attested ? 'attested' : checks.failed ? 'failed' : 'not_attested';
  }
  if (checks.failed) return report('invalid', subject, named, authority, witness, checks);
  const contractCheck = checks.items.find((item) => item.check === 'unifyid_contract');
  if (authority === 'anchored')
    return report('verified', subject, named, authority, witness, checks);
  if (contractCheck?.status === 'unavailable' && /could not be read/.test(contractCheck.detail))
    return report('unavailable', subject, named, authority, witness, checks);
  return report('not_anchored', subject, named, authority, witness, checks);
}

function mergeRef<T extends object>(base: T | null, override: Partial<T> | undefined): T | null {
  if (
    !override ||
    !Object.values(override).some((value) => value !== undefined && value !== null && value !== '')
  )
    return base;
  const clean = Object.fromEntries(
    Object.entries(override).filter(
      ([, value]) => value !== undefined && value !== null && value !== '',
    ),
  );
  return { ...(base ?? {}), ...clean } as T;
}

function report(
  outcome: Outcome,
  subject: ProofBundle['subject'] | null,
  checkpoint: VerificationReport['checkpoint'],
  authority: VerificationReport['authority'],
  witness: VerificationReport['witness'],
  checks: Checks,
): VerificationReport {
  const failed = checks.first('failed');
  const summary =
    outcome === 'verified'
      ? `Verified. The record is in checkpoint ${checkpoint?.sequence}, signed by UnifyID and held by UnifyID's contract on chain${witness === 'attested' ? ', and Sign Protocol carries the same checkpoint as a second witness' : '; Sign Protocol does not carry it yet'}.`
      : outcome === 'verified_off_chain'
        ? `The record, its proof and UnifyID's signature on checkpoint ${checkpoint?.sequence} verify. Pass --rpc-url to check the chain as well.`
        : outcome === 'not_anchored'
          ? `The record and checkpoint ${checkpoint?.sequence} verify, but UnifyID's contract does not hold that checkpoint yet. Try again later.`
          : outcome === 'not_sealed'
            ? 'Not sealed yet: the record waits for the next hourly checkpoint.'
            : outcome === 'unavailable'
              ? 'The chain could not be read. Check the RPC URL and try again.'
              : `Not verified: ${failed?.detail ?? 'a check failed.'}`;
  return {
    outcome,
    valid: outcome === 'verified' || outcome === 'verified_off_chain',
    subject,
    checkpoint,
    authority,
    witness,
    checks: checks.items,
    summary,
  };
}
