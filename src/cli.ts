#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import {
  verifyConsistencyProof,
  type ConsistencyProofDocument,
  type CheckpointView,
} from './audit-proof.js';
import { parseKeySet, type KeySet } from './keys.js';
import {
  isProofBundle,
  isProofBundleSet,
  verifyCheckpointAnchors,
  verifyProofBundle,
  type ProofBundle,
  type VerificationReport,
  type VerifyOptions,
} from './verify.js';

const USAGE = `UnifyID integrity verifier

Prove a record against UnifyID's signed checkpoints and the public chain, without trusting UnifyID.

Usage:
  unifyid-integrity-verify proof <bundle.json> --keys <keys.json | https URL> [chain options] [--record <record.json>] [--json]
  unifyid-integrity-verify checkpoint <checkpoint.json> --keys <keys.json | https URL> [chain options] [--json]
  unifyid-integrity-verify consistency <consistency-proof.json> --keys <keys.json | https URL> [--json]

Chain options (omit them all to verify off-chain only):
  --rpc-url <url>          RPC endpoint you trust for the chain UnifyID anchors on (required for any chain check)
  --sign-rpc-url <url>     A different endpoint for Sign Protocol (defaults to --rpc-url)
  --chain-id <id>          Expected chain id (Base 8453; Base Sepolia 84532 for testing); overrides the bundle
  --contract <address>     UnifyID anchor contract you trust; overrides the bundle
  --sign-protocol <address> Sign Protocol contract; overrides the bundle
  --sign-hook <address>    UnifyID's Sign Protocol hook; overrides the bundle
  --sign-schema <id>       UnifyID's Sign Protocol schema id; overrides the bundle
  --confirmations <n>      Blocks required on top of the anchoring block (default 1)

Exit codes: 0 verified, 1 not valid (tampered, wrong key, forged checkpoint),
            2 usage error, 3 not decided yet (not sealed, not anchored, chain unreachable).`;

type Flags = Record<string, string | true>;

function parse(argv: string[]): { positional: string[]; flags: Flags } {
  const positional: string[] = [];
  const flags: Flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (['json', 'help'].includes(name)) flags[name] = true;
    else {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('--'))
        throw new UsageError(`--${name} needs a value.`);
      flags[name] = value;
      index += 1;
    }
  }
  return { positional, flags };
}

class UsageError extends Error {}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new UsageError(
      `${path} could not be read as JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function loadKeys(source: string | true | undefined): Promise<KeySet> {
  if (typeof source !== 'string')
    throw new UsageError(
      '--keys is required: a file, or the https URL where UnifyID publishes its checkpoint keys.',
    );
  if (/^https?:\/\//i.test(source)) {
    const url = new URL(source);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !local)
      throw new UsageError('Keys are fetched over https only.');
    const response = await fetch(url, { headers: { accept: 'application/json' } });
    if (!response.ok) throw new UsageError(`The keys could not be fetched (${response.status}).`);
    return parseKeySet(await response.json());
  }
  return parseKeySet(await readJson(source));
}

function text(flags: Flags, name: string): string | undefined {
  const value = flags[name];
  return typeof value === 'string' ? value : undefined;
}

function optionsFrom(flags: Flags, keys: KeySet): VerifyOptions {
  const rpcUrl = text(flags, 'rpc-url');
  const chainId = text(flags, 'chain-id');
  const confirmations = text(flags, 'confirmations');
  if (confirmations !== undefined && !/^\d+$/.test(confirmations))
    throw new UsageError('--confirmations must be a whole number.');
  for (const name of ['contract', 'sign-protocol', 'sign-hook'])
    if (text(flags, name) && !/^0x[0-9a-fA-F]{40}$/.test(text(flags, name)!))
      throw new UsageError(`--${name} must be an address.`);
  if (
    !rpcUrl &&
    ['sign-rpc-url', 'contract', 'sign-hook', 'sign-protocol'].some((name) => text(flags, name))
  )
    throw new UsageError('Chain options need --rpc-url.');
  return {
    keys,
    chain: rpcUrl
      ? {
          rpcUrl,
          signRpcUrl: text(flags, 'sign-rpc-url'),
          minConfirmations: confirmations ? Number(confirmations) : 1,
        }
      : undefined,
    contract: { chainId, contractAddress: text(flags, 'contract') },
    sign: {
      chainId,
      signProtocolAddress: text(flags, 'sign-protocol'),
      hookAddress: text(flags, 'sign-hook'),
      schemaId: text(flags, 'sign-schema'),
      anchorContractAddress: text(flags, 'contract'),
    },
  };
}

const MARK: Record<string, string> = {
  passed: 'PASS',
  failed: 'FAIL',
  skipped: 'SKIP',
  unavailable: 'WAIT',
};

function print(reports: VerificationReport[], json: boolean) {
  if (json) {
    process.stdout.write(
      `${JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2)}\n`,
    );
    return;
  }
  for (const result of reports) {
    if (result.subject)
      process.stdout.write(
        `\n${result.subject.kind} ${result.subject.id} (${result.subject.stream} stream)\n`,
      );
    for (const check of result.checks)
      process.stdout.write(`  [${MARK[check.status]}] ${check.check}: ${check.detail}\n`);
    process.stdout.write(`  => ${result.outcome.toUpperCase()}: ${result.summary}\n`);
  }
}

function exitCode(reports: VerificationReport[]): number {
  if (reports.some((result) => result.outcome === 'invalid')) return 1;
  if (reports.every((result) => result.valid)) return 0;
  return 3;
}

async function main(argv: string[]): Promise<number> {
  const { positional, flags } = parse(argv);
  if (flags.help || !positional.length) {
    process.stdout.write(`${USAGE}\n`);
    return flags.help ? 0 : 2;
  }
  const [command, file] = positional;

  if (!file) throw new UsageError(`${command} needs a file.`);
  const json = flags.json === true;

  if (command === 'proof') {
    const keys = await loadKeys(flags.keys);
    const document = await readJson(file);
    const record = text(flags, 'record') ? await readJson(text(flags, 'record')!) : undefined;
    const bundles: ProofBundle[] = isProofBundleSet(document)
      ? document.bundles
      : isProofBundle(document)
        ? [document]
        : [];
    if (!bundles.length) throw new UsageError(`${file} is not a UnifyID proof bundle.`);
    if (record !== undefined && bundles.length !== 1)
      throw new UsageError('--record applies to a file with one proof.');
    const options = optionsFrom(flags, keys);
    const reports: VerificationReport[] = [];
    for (const bundle of bundles)
      reports.push(await verifyProofBundle(bundle, { ...options, record }));
    print(reports, json);
    return exitCode(reports);
  }
  if (command === 'checkpoint') {
    const keys = await loadKeys(flags.keys);
    const document = (await readJson(file)) as { data?: unknown } & CheckpointView;
    const checkpoint = (
      document && typeof document === 'object' && 'data' in document ? document.data : document
    ) as CheckpointView;
    const result = await verifyCheckpointAnchors(checkpoint, optionsFrom(flags, keys));
    print([result], json);
    return exitCode([result]);
  }
  if (command === 'consistency') {
    const keys = await loadKeys(flags.keys);
    const checks = verifyConsistencyProof((await readJson(file)) as ConsistencyProofDocument, keys);
    const failed = checks.failed;
    if (json)
      process.stdout.write(
        `${JSON.stringify({ valid: !failed, checks: checks.items }, null, 2)}\n`,
      );
    else {
      for (const check of checks.items)
        process.stdout.write(`  [${MARK[check.status]}] ${check.check}: ${check.detail}\n`);
      process.stdout.write(`  => ${failed ? 'INVALID' : 'CONSISTENT'}\n`);
    }
    return failed ? 1 : 0;
  }
  throw new UsageError(`Unknown command ${command}.`);
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n\n${USAGE}\n`);
      process.exitCode = 2;
    } else {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 3;
    }
  },
);
