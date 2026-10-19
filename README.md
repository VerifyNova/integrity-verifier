# UnifyID integrity verifier

Check for yourself that UnifyID has not rewritten its records. You do not need
to trust UnifyID, its servers or its database: the verifier checks a record
against UnifyID's signed hourly checkpoint and against the public chain, through
an RPC endpoint **you** choose.

- **Open source**, MIT licence: [github.com/VerifyNova/integrity-verifier](https://github.com/VerifyNova/integrity-verifier).
- **Command line and library.**
- **Nothing to trust but maths and a chain.** The only thing you ever fetch from
  UnifyID is its list of public signing keys, and you can keep your own copy.
- **Built from this source.** Every release is published by the repository's
  GitHub Actions workflow with npm provenance, so npm shows the commit and the
  workflow run it was built from.

## What it proves

UnifyID records every sealed event (data released to an app, a staff access
to your record, a public transparency fact) in an append-only log. Every hour, everything new is sealed into one checkpoint and
published twice on Base:

1. **UnifyID's anchor contract, the authority.** It accepts a checkpoint only if
   it is signed by a key UnifyID's multisig registered, is sent by an authorised
   wallet, and follows the previous checkpoint without a gap or fork.
2. **Sign Protocol, the second witness.** The same bytes are attested under
   UnifyID's schema, whose hook reads the contract's list of authorised signers.

Given a proof bundle (the file you download from **See proof** in UnifyID), the
verifier checks, in order:

| # | Check | What passing means |
|---|-------|--------------------|
| 1 | `record` | The record in the file (or one you supply with `--record`) hashes to the sealed content hash. A changed field fails. |
| 2 | `leaf` | The salted leaf is `SHA-256(0x00 ‖ salt ‖ contentHash)`. |
| 3 | `inclusion` | The RFC 6962 inclusion proof leads from the leaf to the stream's Merkle root. |
| 4 | `stream_head` | That root is the stream head the checkpoint commits to. |
| 5 | `combined_root` | The five stream heads combine to the checkpoint's root. |
| 6 | `statement` | The 256-byte checkpoint statement decodes, matches, and hashes to the checkpoint fingerprint. |
| 7 | `signing_key` | The statement names one of UnifyID's published keys. |
| 8 | `signature` | That key signed the statement (ES256, low-S). |
| 9 | `unifyid_contract` | UnifyID's contract holds this fingerprint at this sequence (and, when the file names it, the transaction emitted `CheckpointAnchored` with these exact bytes), with enough confirmations. |
| 10 | `sign_protocol` | Sign Protocol's attestation, found through UnifyID's hook, carries the identical statement and signature. |

A checkpoint forged with a stolen or re-used UnifyID key passes checks 1 to 8
but fails check 9: the contract already holds a different checkpoint at that
sequence, and it cannot be replaced.

The verifier never treats a chain record as proof that what a record says is
true. It proves the record is the one UnifyID sealed, and that it has not
changed since.

## Install

```sh
npm install --global @vn.unifyid/integrity-verifier
```

or run it once without installing:

```sh
npx @vn.unifyid/integrity-verifier proof unifyid-proof.json --keys keys.json --rpc-url https://mainnet.base.org
```

Node.js 20 or later. To check that the package you installed was built from this
repository, run `npm audit signatures`.

## Command line

UnifyID anchors on **Base mainnet** (chain id `8453`). Base Sepolia (chain id
`84532`) is used only for testing and rehearsals; a proof from a test system
names it, and the verifier then needs a Base Sepolia endpoint.

```sh
# A record from "See proof": everything, including the chain
unifyid-integrity-verify proof unifyid-proof.json \
  --keys https://api.unifyid.com/.well-known/unifyid-checkpoint-keys.json \
  --rpc-url https://mainnet.base.org

# The same, insisting on Base mainnet whatever the file says
unifyid-integrity-verify proof unifyid-proof.json --keys keys.json \
  --rpc-url https://mainnet.base.org --chain-id 8453

# A proof from a test system on Base Sepolia
unifyid-integrity-verify proof unifyid-proof.json --keys keys.json \
  --rpc-url https://sepolia.base.org --chain-id 84532

# Off-chain only (no RPC URL): checks 1 to 8
unifyid-integrity-verify proof unifyid-proof.json --keys keys.json

# Check the record from your own export instead of the one in the file
unifyid-integrity-verify proof unifyid-proof.json --record my-record.json --keys keys.json --rpc-url ...

# A checkpoint from the public transparency page: signature, contract, witness
unifyid-integrity-verify checkpoint unifyid-checkpoint-41.json --keys keys.json --rpc-url ...

# Two checkpoints: every stream only grew between them
unifyid-integrity-verify consistency consistency-proof.json --keys keys.json
```

Options:

| Option | Meaning |
|--------|---------|
| `--keys <file or https URL>` | UnifyID's published checkpoint keys (required). A file you keep is the strongest choice. |
| `--rpc-url <url>` | An RPC endpoint you trust for the chain UnifyID anchors on. Without it, nothing on chain is checked. |
| `--sign-rpc-url <url>` | A different endpoint for Sign Protocol (defaults to `--rpc-url`). |
| `--chain-id <id>` | The chain you expect: Base mainnet `8453` (UnifyID's production log), or Base Sepolia `84532` (testing). It overrides the chain the file names, and the RPC endpoint must serve that chain or the check fails. |
| `--contract <address>` | UnifyID's anchor contract, if you want to use an address you got yourself rather than the one in the file. |
| `--sign-protocol <address>`, `--sign-hook <address>`, `--sign-schema <id>` | The same, for Sign Protocol. |
| `--confirmations <n>` | Blocks required on top of the anchoring block (default 1). |
| `--json` | Machine-readable report. |

Exit codes: `0` verified; `1` not valid (tampered, wrong key, forged); `2` usage
error; `3` not decided yet (not sealed, not anchored yet, or the chain could not
be read).

## Library

```sh
npm install @vn.unifyid/integrity-verifier
```

```ts
import { readFile } from 'node:fs/promises';
import { parseKeySet, verifyProofBundle } from '@vn.unifyid/integrity-verifier';

const keys = parseKeySet(JSON.parse(await readFile('keys.json', 'utf8')));
const bundle = JSON.parse(await readFile('unifyid-proof.json', 'utf8'));
const report = await verifyProofBundle(bundle, {
  keys,
  // Base mainnet; for a Base Sepolia test proof use a Base Sepolia endpoint.
  chain: { rpcUrl: 'https://mainnet.base.org', minConfirmations: 3 },
  contract: { chainId: '8453' },
  sign: { chainId: '8453' },
});
if (report.outcome !== 'verified') throw new Error(report.summary);
```

The package is ESM only (`import`, not `require`).

Exports include:

- `verifyProofBundle(bundle, options)` and `verifyCheckpointAnchors(checkpoint, options)`, returning
  `{ outcome, valid, authority, witness, checks, summary }`;
- `verifyInclusionProof`, `verifyConsistencyProof`, `verifyCheckpoint` (off-chain);
- `verifyOnContract`, `verifyOnSignProtocol` (chain reads through viem);
- RFC 6962 helpers: `leafHash`, `nodeHash`, `verifyInclusion`, `verifyConsistency`,
  `merkleTreeHash`, `inclusionPath`, `consistencyProof`;
- statement helpers: `decodeStatement`, `encodeStatement`, `statementFingerprint`,
  `combinedRoot`, `logIdFor`, `signingKeyFingerprint`;
- `parseKeySet`, `verifyEs256`.

## Formats

**Proof bundle** (`unifyid.proof-bundle`, version 1):

```jsonc
{
  "format": "unifyid.proof-bundle", "version": 1, "generatedAt": "ISO",
  "subject": { "kind": "ledger_entry | audit_event | transparency_fact", "id": "…", "eventId": "uuid", "stream": "disclosure", "occurredAt": "ISO", "description": "…" },
  "state": "recorded | sealed | anchored_one_channel | anchored_both",
  "recordWithheld": null,               // why the record is not in the file, when it is not
  "proof": { /* unifyid.audit.inclusion-proof v1, null while only recorded */ },
  "anchors": {
    "unifyid_contract": { "chainId": "8453", "contractAddress": "0x…", "sequence": "41", "transactionHash": "0x…|null", "blockNumber": "…|null", "status": "…" },
    "sign_protocol": { "chainId": "8453", "signProtocolAddress": "0x…", "hookAddress": "0x…", "schemaId": "…", "attestationId": "…|null", "transactionHash": "0x…|null", "status": "…" }
  },
  "keysUrl": "https://…/.well-known/unifyid-checkpoint-keys.json",
  "howToVerify": "unifyid-integrity-verify proof …"
}
```

A file for several records is `unifyid.proof-bundle-set` with `bundles: [...]`.

**Checkpoint statement** (version 1), exactly 256 bytes, the Solidity ABI
encoding of `(uint16 version, bytes32 logId, uint64 sequence, uint64 periodStart,
uint64 periodEnd, bytes32 combinedRoot, bytes32 previousCombinedRoot, bytes32
signingKeyFingerprint)`. `fingerprint = SHA-256(statement)`; the signature is
ES256 over the statement as 64 bytes `r ‖ s`, low-S.

**Combined root**: `SHA-256(0x02 ‖ H(audit) ‖ H(access) ‖ H(disclosure) ‖
H(receipts) ‖ H(transparency))`, `H(s) = uint8(len(name)) ‖ name ‖
uint64_be(treeSize) ‖ root`; an empty stream is `(0, SHA-256(""))`.

**Sign Protocol attestation data**: the statement's eight fields followed by
`bytes signature`, 384 bytes; the first 256 bytes are the statement.

## Trust notes

- Use an RPC endpoint you control or trust. A lying endpoint can hide an anchor
  (the verifier then says "not anchored"), but cannot make a forged record verify
  against a contract it does not control. Base's public endpoint
  (`https://mainnet.base.org`) is one that UnifyID does not use for anchoring.
- Ask for as many confirmations as your purpose needs with `--confirmations`
  (default 1).
- Sign Protocol's contract on Base mainnet is
  `0x2b3224D080452276a76690341e5Cfa81A945a985` (Base Sepolia:
  `0x4e4af2a21ebf62850fD99Eb6253E1eFBb56098cD`). The verifier reads it at the
  address the file names; pass `--sign-protocol` to use the one you looked up.
- Compare the contract and hook addresses with ones you obtained independently
  (UnifyID publishes them on its transparency page), or pass them with
  `--contract` and `--sign-hook`.
- Keep a copy of the keys. A key UnifyID retires stays in the published list so
  old checkpoints keep verifying.

## Development

```sh
npm ci
npm run build
npm test
```

`npm test` runs the suites in `test/`, including the command line, built from
this package, against a local JSON-RPC endpoint that answers as Base mainnet.

A release is a tag `v<version>` equal to the `version` in `package.json`: the
release workflow checks that, builds, tests and publishes with npm provenance.
