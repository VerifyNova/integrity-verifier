import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { decodeFunctionData, encodeFunctionResult, numberToHex, type Abi, type Hex as ViemHex } from 'viem';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SIGN_PROTOCOL_ABI, UNIFYID_ANCHOR_ABI, UNIFYID_SIGN_HOOK_ABI } from '../src/index.js';
import {
  anchoredWorld,
  anchors,
  answer,
  BASE_MAINNET,
  BASE_SEPOLIA,
  checkpoint,
  CONTRACT,
  HOOK,
  SIGN,
  SUBMITTER,
  TX,
  type World,
} from './fixtures.js';

/**
 * The command line on Base mainnet's chain id, end to end: the CLI as published (built from this
 * package), a checkpoint file naming chain 8453, and a JSON-RPC endpoint on this machine that
 * answers as UnifyID's contract, its Sign Protocol hook and Sign Protocol would. The CLI reads the
 * RPC's chain id, the confirmations, the contract and Sign Protocol at the addresses in the file,
 * exactly as it does against a real Base endpoint.
 */

const PACKAGE = resolve(__dirname, '..');
const CLI = join(PACKAGE, 'dist', 'cli.js');

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const abiFor = (to: string) =>
  (same(to, CONTRACT) ? UNIFYID_ANCHOR_ABI : same(to, HOOK) ? UNIFYID_SIGN_HOOK_ABI : same(to, SIGN) ? SIGN_PROTOCOL_ABI : null) as Abi | null;

type RpcCall = { id: number; method: string; params: Array<{ to: string; data: ViemHex }> };

/** One JSON-RPC answer, from the same world the library tests use. */
function respond(world: World, call: RpcCall): unknown {
  switch (call.method) {
    case 'eth_chainId':
      return numberToHex(world.chainId ?? BASE_SEPOLIA);
    case 'eth_blockNumber':
      return numberToHex(world.head ?? 110n);
    case 'eth_call': {
      const { to, data } = call.params[0]!;
      const abi = abiFor(to);
      if (!abi) throw new Error(`no contract at ${to}`);
      const { functionName, args } = decodeFunctionData({ abi, data });
      return encodeFunctionResult({ abi, functionName, result: answer(world, functionName, args ?? []) } as never);
    }
    case 'eth_getTransactionReceipt': {
      const receipt = world.receipt!;
      const blockHash = `0x${'cd'.repeat(32)}`;
      return {
        transactionHash: TX,
        transactionIndex: '0x0',
        blockHash,
        blockNumber: numberToHex(receipt.blockNumber),
        from: SUBMITTER,
        to: CONTRACT,
        cumulativeGasUsed: '0x5208',
        gasUsed: '0x5208',
        effectiveGasPrice: '0x1',
        contractAddress: null,
        logs: receipt.logs.map((log, index) => ({
          ...log,
          blockHash,
          blockNumber: numberToHex(receipt.blockNumber),
          transactionHash: TX,
          transactionIndex: '0x0',
          logIndex: numberToHex(index),
          removed: false,
        })),
        logsBloom: `0x${'00'.repeat(256)}`,
        status: receipt.status === 'success' ? '0x1' : '0x0',
        type: '0x2',
      };
    }
    default:
      throw new Error(`unexpected method ${call.method}`);
  }
}

async function body(request: IncomingMessage): Promise<string> {
  let text = '';
  for await (const chunk of request) text += String(chunk);
  return text;
}

let world: World = {};
const server = createServer((request, response) => {
  void body(request).then((text) => {
    const parsed = JSON.parse(text) as RpcCall | RpcCall[];
    const reply = (call: RpcCall) => {
      try {
        return { jsonrpc: '2.0', id: call.id, result: respond(world, call) };
      } catch (error) {
        return { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: String(error) } };
      }
    };
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(Array.isArray(parsed) ? parsed.map(reply) : reply(parsed)));
  });
});

let rpcUrl = '';
let work = '';

/** The CLI in a child process that does not block this one, so the endpoint above can answer it. */
function cli(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI, ...args]);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += String(chunk)));
    child.stderr.on('data', (chunk) => (stderr += String(chunk)));
    child.on('close', (code) => done({ code, stdout, stderr }));
  });
}

/** Writes the checkpoint file and keys the CLI reads, for a checkpoint anchored on `chainId`. */
function files(chainId: number) {
  const { view, keys } = checkpoint();
  const checkpointFile = join(work, `checkpoint-${chainId}-${Date.now()}.json`);
  const keysFile = join(work, `keys-${chainId}-${Date.now()}.json`);
  // The shape of GET /v1/public/transparency/anchored-checkpoints/:sequence.
  writeFileSync(checkpointFile, JSON.stringify({ data: { ...view, anchors: anchors(view, chainId) } }));
  writeFileSync(keysFile, JSON.stringify(keys));
  return { view, checkpointFile, keysFile };
}

beforeAll(async () => {
  // The CLI is tested as it is published: built from this package by its own TypeScript.
  const tsc = createRequire(join(PACKAGE, 'package.json')).resolve('typescript/bin/tsc');
  execFileSync(process.execPath, [tsc, '-p', join(PACKAGE, 'tsconfig.json')], { stdio: 'pipe' });
  work = mkdtempSync(join(tmpdir(), 'integrity-verifier-cli-'));
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', () => done()));
  rpcUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}, 120_000);

afterAll(() => {
  server.close();
  rmSync(work, { recursive: true, force: true });
});

describe('unifyid-integrity-verify checkpoint on Base mainnet (chain 8453)', () => {
  it('verifies a checkpoint anchored on chain 8453 through an RPC serving chain 8453, and exits 0', async () => {
    const { view, checkpointFile, keysFile } = files(BASE_MAINNET);
    world = { ...anchoredWorld(view), chainId: BASE_MAINNET };
    const result = await cli(['checkpoint', checkpointFile, '--keys', keysFile, '--rpc-url', rpcUrl, '--json']);
    expect(result.code, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout) as { outcome: string; authority: string; witness: string; checks: Array<{ check: string; detail: string }> };
    expect(report).toMatchObject({ outcome: 'verified', authority: 'anchored', witness: 'attested' });
    expect(report.checks.find((check) => check.check === 'unifyid_contract')!.detail).toContain(`on chain ${BASE_MAINNET}`);
    expect(report.checks.find((check) => check.check === 'sign_protocol')!.detail).toContain(`on chain ${BASE_MAINNET}`);
  });

  it('--chain-id 8453 overrides the file, and an RPC on another chain is refused (exit 1)', async () => {
    const sepoliaFile = files(BASE_SEPOLIA);
    world = { ...anchoredWorld(sepoliaFile.view), chainId: BASE_MAINNET };
    const overridden = await cli(['checkpoint', sepoliaFile.checkpointFile, '--keys', sepoliaFile.keysFile, '--rpc-url', rpcUrl, '--chain-id', String(BASE_MAINNET)]);
    expect(overridden.code, overridden.stdout).toBe(0);
    expect(overridden.stdout).toContain('=> VERIFIED');

    const mainnetFile = files(BASE_MAINNET);
    world = { ...anchoredWorld(mainnetFile.view), chainId: BASE_SEPOLIA };
    const wrongChain = await cli(['checkpoint', mainnetFile.checkpointFile, '--keys', mainnetFile.keysFile, '--rpc-url', rpcUrl]);
    expect(wrongChain.code).toBe(1);
    expect(wrongChain.stdout).toContain(`The RPC URL serves chain ${BASE_SEPOLIA}, but the anchor is on chain ${BASE_MAINNET}.`);
  });

  it('waits (exit 3) until the anchoring block has the confirmations asked for', async () => {
    const { view, checkpointFile, keysFile } = files(BASE_MAINNET);
    world = { ...anchoredWorld(view), chainId: BASE_MAINNET };
    const result = await cli(['checkpoint', checkpointFile, '--keys', keysFile, '--rpc-url', rpcUrl, '--confirmations', '20']);
    expect(result.code).toBe(3);
    expect(result.stdout).toContain('11 of 20 confirmations');
  });
});
