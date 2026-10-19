import { createHash } from 'node:crypto';
import { pad, toHex, type Hex as ViemHex } from 'viem';
import { describe, expect, it } from 'vitest';
import { decodeAttestationData, verifyCheckpointAnchors, type CheckpointView, type PublishedKey } from '../src/index.js';
import {
  anchoredLog,
  anchoredWorld,
  anchors,
  answer,
  attestationData,
  BASE_MAINNET,
  BASE_SEPOLIA,
  checkpoint,
  TX,
  type World,
} from './fixtures.js';

/**
 * The verifier's chain checks (9 and 10), against a fake RPC client that
 * answers the contract, the hook and Sign Protocol exactly as the compiled
 * ABIs shape them. These were the only checks in the package without a test,
 * and they are the two that make a forged checkpoint fail: a key can be
 * stolen, the contract's slot for a sequence cannot be replaced.
 */

/** A viem public client as far as the verifier uses one. */
function client(world: World) {
  return {
    async getChainId() {
      if (world.fail) throw new Error('fetch failed');
      return world.chainId ?? BASE_SEPOLIA;
    },
    async getBlockNumber() {
      return world.head ?? 110n;
    },
    async getTransactionReceipt() {
      if (!world.receipt) throw new Error('receipt not found');
      return world.receipt;
    },
    async readContract({ functionName, args }: { address: string; functionName: string; args?: unknown[] }) {
      return answer(world, functionName, args);
    },
  };
}

async function run(view: CheckpointView, keys: { keys: PublishedKey[] }, world: World, extra: Record<string, unknown> = {}, chainId = BASE_SEPOLIA) {
  const fake = client(world);
  return verifyCheckpointAnchors(
    { ...view, anchors: anchors(view, chainId) },
    { keys, chain: { rpcUrl: 'http://rpc.test', client: fake as never, signClient: fake as never, minConfirmations: 1 }, ...extra },
  );
}

const status = (report: { checks: Array<{ check: string; status: string; detail: string }> }, name: string) =>
  report.checks.find((check) => check.check === name)!;

describe('the attestation data layout', () => {
  it('reads the statement and signature back out of what the Sign publisher writes, and nothing else', () => {
    const { view } = checkpoint();
    const decoded = decodeAttestationData(attestationData(view.statement, view.signature));
    expect(decoded).toEqual({ statement: view.statement, signature: view.signature });
    // A different offset word, a short body, or non-hex: not UnifyID's layout.
    const wrongOffset = `${view.statement}${pad(toHex(0x140), { size: 32 }).slice(2)}${pad(toHex(64), { size: 32 }).slice(2)}${view.signature.slice(2)}`;
    expect(decodeAttestationData(wrongOffset)).toBeNull();
    expect(decodeAttestationData(view.statement)).toBeNull();
    expect(decodeAttestationData(`0x${'zz'.repeat(384)}`)).toBeNull();
  });
});

describe("UnifyID's contract, the authority", () => {
  it('verifies a checkpoint the contract holds at its sequence, with the anchoring transaction and enough confirmations', async () => {
    const { view, keys } = checkpoint();
    const report = await run(view, keys, anchoredWorld(view));
    expect(report).toMatchObject({ outcome: 'verified', valid: true, authority: 'anchored', witness: 'attested' });
    expect(status(report, 'unifyid_contract')).toMatchObject({ status: 'passed', detail: expect.stringContaining(`transaction ${TX}`) });
    expect(status(report, 'unifyid_contract').detail).toContain('11 confirmations');
    expect(status(report, 'sign_protocol')).toMatchObject({ status: 'passed', detail: expect.stringContaining('authorised submitter') });
    expect(report.summary).toContain('second witness');
  });

  it('calls a forged checkpoint forged: the contract already holds another fingerprint at that sequence', async () => {
    const { view, keys } = checkpoint();
    const other = createHash('sha256').update('the real one').digest('hex');
    const world: World = { ...anchoredWorld(view), sequenceOf: {}, stored: { '41': { fingerprint: other, combinedRoot: view.combinedRoot, periodEnd: 1700003600n, blockNumber: 90n } } };
    const report = await run(view, keys, world);
    expect(report).toMatchObject({ outcome: 'invalid', valid: false, authority: 'failed' });
    expect(status(report, 'unifyid_contract')).toMatchObject({ status: 'failed', detail: expect.stringContaining('Forged checkpoint') });
  });

  it('waits, rather than fails, while the contract does not hold the checkpoint yet', async () => {
    const { view, keys } = checkpoint();
    const report = await run(view, keys, { ...anchoredWorld(view), sequenceOf: {}, stored: {} });
    expect(report).toMatchObject({ outcome: 'not_anchored', valid: false, authority: 'not_anchored' });
    expect(status(report, 'unifyid_contract')).toMatchObject({ status: 'unavailable', detail: expect.stringContaining('not on UnifyID') });
  });

  it('refuses the wrong chain, a contract for another log, a fingerprint at another sequence, and different stored bytes', async () => {
    const { view, keys } = checkpoint();
    const base = anchoredWorld(view);
    for (const [world, expected] of [
      [{ ...base, chainId: 8453 }, /serves chain 8453/],
      [{ ...base, logId: createHash('sha256').update('another log').digest('hex') }, /different log/],
      [{ ...base, sequenceOf: { [`0x${view.fingerprint}`]: 40n } }, /at sequence 40, not 41/],
      [{ ...base, stored: { '41': { ...base.stored!['41']!, combinedRoot: createHash('sha256').update('x').digest('hex') } } }, /different checkpoint at sequence 41/],
    ] as const) {
      const report = await run(view, keys, world as World);
      expect(report.outcome).toBe('invalid');
      expect(status(report, 'unifyid_contract')).toMatchObject({ status: 'failed', detail: expect.stringMatching(expected) });
    }
  });

  it('refuses a transaction that anchored different statement bytes, and one that did not anchor this checkpoint', async () => {
    const { view, keys } = checkpoint();
    const base = anchoredWorld(view);
    const tampered = `0x${'00'.repeat(256)}`;
    const wrongBytes = await run(view, keys, { ...base, receipt: { status: 'success', blockNumber: 100n, logs: [anchoredLog(view, { statement: tampered })] } });
    expect(status(wrongBytes, 'unifyid_contract')).toMatchObject({ status: 'failed', detail: expect.stringContaining('different statement bytes') });
    const noEvent = await run(view, keys, { ...base, receipt: { status: 'success', blockNumber: 100n, logs: [] } });
    expect(status(noEvent, 'unifyid_contract')).toMatchObject({ status: 'failed', detail: expect.stringContaining('did not anchor this checkpoint') });
  });

  it('waits for confirmations, and reports an unreadable chain as undecided rather than invalid', async () => {
    const { view, keys } = checkpoint();
    const young = await run(view, keys, { ...anchoredWorld(view), head: 100n }, { chain: undefined });
    // No chain options at all: off-chain only, both chain checks skipped.
    expect(young).toMatchObject({ outcome: 'verified_off_chain', valid: true });
    const fake = client({ ...anchoredWorld(view), head: 101n });
    const short = await verifyCheckpointAnchors({ ...view, anchors: anchors(view) }, { keys, chain: { rpcUrl: 'http://rpc.test', client: fake as never, signClient: fake as never, minConfirmations: 6 } });
    expect(short).toMatchObject({ outcome: 'not_anchored' });
    expect(status(short, 'unifyid_contract')).toMatchObject({ status: 'unavailable', detail: expect.stringContaining('2 of 6 confirmations') });
    const down = await run(view, keys, { ...anchoredWorld(view), fail: true });
    expect(down).toMatchObject({ outcome: 'unavailable', valid: false });
    expect(status(down, 'unifyid_contract')).toMatchObject({ status: 'unavailable', detail: expect.stringContaining('could not be read') });
  });
});

describe('Sign Protocol, the second witness', () => {
  it('reports a split view when Sign carries another fingerprint for the sequence, or different bytes', async () => {
    const { view, keys } = checkpoint();
    const base = anchoredWorld(view);
    const other = createHash('sha256').update('other').digest('hex');
    const split = await run(view, keys, { ...base, attestationOf: {}, fingerprintAt: { '41': other } });
    expect(split.outcome).toBe('invalid');
    expect(status(split, 'sign_protocol')).toMatchObject({ status: 'failed', detail: expect.stringContaining('Split view') });
    const bytes = await run(view, keys, { ...base, attestation: { ...base.attestation!, data: attestationData(`0x${'11'.repeat(256)}`, view.signature) } });
    expect(status(bytes, 'sign_protocol')).toMatchObject({ status: 'failed', detail: expect.stringContaining('different statement bytes') });
  });

  it('refuses a hook bound to another contract, a schema not guarded by the hook, a revoked attestation, and a foreign layout', async () => {
    const { view, keys } = checkpoint();
    const base = anchoredWorld(view);
    for (const [world, expected] of [
      [{ ...base, hookAnchor: `0x${'99'.repeat(20)}` }, /not UnifyID's hook/],
      [{ ...base, schemaHook: `0x${'99'.repeat(20)}` }, /not guarded by UnifyID's hook/],
      [{ ...base, attestation: { ...base.attestation!, revoked: true } }, /revoked/],
      [{ ...base, attestation: { ...base.attestation!, data: '0x1234' as ViemHex } }, /schema's layout/],
      [{ ...base, attestation: { ...base.attestation!, schemaId: 8n } }, /schema 8, not UnifyID's schema 7/],
    ] as const) {
      const report = await run(view, keys, world as World);
      expect(report.outcome).toBe('invalid');
      expect(status(report, 'sign_protocol')).toMatchObject({ status: 'failed', detail: expect.stringMatching(expected) });
    }
  });

  it('is a witness, not a gate: a checkpoint the contract holds verifies while Sign does not carry it yet', async () => {
    const { view, keys } = checkpoint();
    const report = await run(view, keys, { ...anchoredWorld(view), attestationOf: {} });
    expect(report).toMatchObject({ outcome: 'verified', valid: true, authority: 'anchored', witness: 'not_attested' });
    expect(status(report, 'sign_protocol')).toMatchObject({ status: 'unavailable' });
    expect(report.summary).toContain('Sign Protocol does not carry it yet');
  });

  it('says so when the attester is no longer an authorised submitter, without failing the statement it already proves', async () => {
    const { view, keys } = checkpoint();
    const report = await run(view, keys, { ...anchoredWorld(view), isSubmitter: false });
    expect(report.outcome).toBe('verified');
    expect(status(report, 'sign_protocol').detail).toContain('no longer an authorised submitter');
  });
});

describe('Base mainnet (chain 8453)', () => {
  it('verifies end to end: the RPC chain check, confirmations, the contract, and Sign Protocol at the addresses the file names', async () => {
    const { view, keys } = checkpoint();
    const report = await run(view, keys, { ...anchoredWorld(view), chainId: BASE_MAINNET }, {}, BASE_MAINNET);
    expect(report).toMatchObject({ outcome: 'verified', valid: true, authority: 'anchored', witness: 'attested' });
    expect(status(report, 'unifyid_contract').detail).toContain(`on chain ${BASE_MAINNET} holds checkpoint 41`);
    expect(status(report, 'unifyid_contract').detail).toContain('11 confirmations');
    expect(status(report, 'sign_protocol').detail).toContain(`on chain ${BASE_MAINNET} carries the identical statement`);
  });

  it('refuses a Base Sepolia endpoint for a mainnet anchor, and a mainnet endpoint for a Base Sepolia one', async () => {
    const { view, keys } = checkpoint();
    const sepoliaRpc = await run(view, keys, { ...anchoredWorld(view), chainId: BASE_SEPOLIA }, {}, BASE_MAINNET);
    expect(sepoliaRpc.outcome).toBe('invalid');
    expect(status(sepoliaRpc, 'unifyid_contract').detail).toBe(`The RPC URL serves chain ${BASE_SEPOLIA}, but the anchor is on chain ${BASE_MAINNET}.`);
    const mainnetRpc = await run(view, keys, { ...anchoredWorld(view), chainId: BASE_MAINNET }, {}, BASE_SEPOLIA);
    expect(status(mainnetRpc, 'unifyid_contract').detail).toBe(`The RPC URL serves chain ${BASE_MAINNET}, but the anchor is on chain ${BASE_SEPOLIA}.`);
  });

  it('waits for the confirmations asked for, as on any chain', async () => {
    const { view, keys } = checkpoint();
    const report = await run(view, keys, { ...anchoredWorld(view), chainId: BASE_MAINNET, head: 104n }, {}, BASE_MAINNET);
    expect(report.outcome).toBe('verified');
    const fake = client({ ...anchoredWorld(view), chainId: BASE_MAINNET, head: 104n });
    const strict = await verifyCheckpointAnchors(
      { ...view, anchors: anchors(view, BASE_MAINNET) },
      { keys, chain: { rpcUrl: 'https://mainnet.base.org', client: fake as never, signClient: fake as never, minConfirmations: 64 } },
    );
    expect(strict.outcome).toBe('not_anchored');
    expect(status(strict, 'unifyid_contract').detail).toContain('5 of 64 confirmations');
  });
});
