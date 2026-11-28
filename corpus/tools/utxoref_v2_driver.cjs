#!/usr/bin/env node
'use strict';

// JSON-lines driver for the BitVM Arena `utxoref-v2` track.
//
//   node utxoref_v2_driver.cjs <path-to-UTXO-Ref-checkout>
//
// One request per stdin line: {"id": n, "op": "...", "params": {...}}; one response per
// stdout line: {"id": n, "ok": true, "result": ...} or {"id": n, "ok": false, "error": "..."}.
//
// Every template, graph, settlement, recovery and disprove is built and signed by the
// target's own modules, loaded from the checkout. Where a row needs a spend the target's
// API refuses to build (a forged disprove, a co-signed spend to other outputs), the driver
// assembles it from the target's own primitives (transaction serializer, script-path
// sighash, BIP340 signer). Secrets are fixed test values; wire preimages come from a seeded
// generator, so the same requests give the same bytes.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const checkout = path.resolve(process.argv[2] || '');
const targetDir = path.join(checkout, 'bitvm3', 'utxo_referee');
const TARGET_FILES = ['utxoref_v2.js', 'bitvm_assertion_graph_v2.js', 'bitvm_trace_v2.js'];

// Keep stdout for the protocol: anything the target prints goes to stderr.
console.log = (...args) => console.error(...args);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
}

function targetRevision(root) {
  try {
    let gitDir = path.join(root, '.git');
    if (fs.statSync(gitDir).isFile()) {
      const pointer = /^gitdir:\s*(.+)$/m.exec(fs.readFileSync(gitDir, 'utf8'));
      gitDir = path.resolve(root, pointer[1].trim());
    }
    const head = fs.readFileSync(path.join(gitDir, 'HEAD'), 'utf8').trim();
    if (/^[0-9a-f]{40}$/.test(head)) return head;
    const ref = /^ref:\s*(.+)$/.exec(head)[1].trim();
    let common = gitDir;
    const commonFile = path.join(gitDir, 'commondir');
    if (fs.existsSync(commonFile)) common = path.resolve(gitDir, fs.readFileSync(commonFile, 'utf8').trim());
    for (const base of [gitDir, common]) {
      const loose = path.join(base, ref);
      if (fs.existsSync(loose)) return fs.readFileSync(loose, 'utf8').trim();
    }
    for (const line of fs.readFileSync(path.join(common, 'packed-refs'), 'utf8').split('\n')) {
      const match = /^([0-9a-f]{40}) (.+)$/.exec(line.trim());
      if (match && match[2] === ref) return match[1];
    }
    return 'unknown';
  } catch (_err) {
    return 'unknown';
  }
}

const v2 = require(path.join(targetDir, 'utxoref_v2.js'));
const graphs = require(path.join(targetDir, 'bitvm_assertion_graph_v2.js'));
const traces = require(path.join(targetDir, 'bitvm_trace_v2.js'));
const a = require(path.join(targetDir, 'tradelayer_dlc_adaptor_sig.js'));
const tr = require(path.join(targetDir, 'tradelayer_taproot.js'));
const ts = require(path.join(targetDir, 'tradelayer_taproot_script.js'));

// ---- fixed test material ------------------------------------------------------------

const DOMAIN = 'bitvm-arena/utxoref-v2/';
const scalarHex = (name) => sha256(DOMAIN + name).toString('hex');
const SECRETS = { operator: scalarHex('operator'), challenger: scalarHex('challenger') };
const XONLY = Object.fromEntries(Object.entries(SECRETS).map(([role, secret]) =>
  [role, a.xOnlyPubkey(BigInt(`0x${secret}`)).toString('hex')]));
const aux = (name) => sha256(`${DOMAIN}aux/${name}`);

const SIGNER_PRIVATE = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), sha256(`${DOMAIN}state-signer`)]),
  format: 'der',
  type: 'pkcs8'
});
const SIGNER_PUBLIC = crypto.createPublicKey(SIGNER_PRIVATE);
const SIGNER_KEY_ID = v2.publicKeyId(SIGNER_PUBLIC);

const IN_STATE = 'state_checkpoint_valid';
const IN_PAYOUT = 'payout_vector_exact';
const OUT = 'settlement_authorized';
const GATES = [{ type: 'and', inputs: [IN_STATE, IN_PAYOUT], output: OUT }];

function seededRandom(seed) {
  let counter = 0;
  return (size) => {
    const chunks = [];
    while (Buffer.concat(chunks).length < size) chunks.push(sha256(`${DOMAIN}wire/${seed}/${counter++}`));
    return Buffer.concat(chunks).subarray(0, size);
  };
}

const contexts = new Map();
function context(name) {
  const found = contexts.get(name);
  if (!found) throw new Error(`unknown context ${name}`);
  return found;
}

// The caller's trust configuration. currentHeight is passed only when the caller gives one.
function verification(ctx, options = {}) {
  const result = {
    trustedSigners: { [SIGNER_KEY_ID]: SIGNER_PUBLIC },
    expectedNetwork: ctx.network,
    expectedGenesisHash: ctx.genesisHash
  };
  if (options.currentHeight !== undefined && options.currentHeight !== null) result.currentHeight = options.currentHeight;
  if (options.maxAgeBlocks !== undefined && options.maxAgeBlocks !== null) result.maxAgeBlocks = options.maxAgeBlocks;
  return result;
}

function publicLeaves(template) {
  return template.leaves.map((leaf) => ({
    id: leaf.id, kind: leaf.kind, scriptHex: leaf.scriptHex, controlBlock: leaf.controlBlock
  }));
}

function leafOf(template, id) {
  const leaf = template.leaves.find((candidate) => candidate.id === id);
  if (!leaf) throw new Error(`assertion leaf ${id} is absent`);
  return leaf;
}

// ---- operations ---------------------------------------------------------------------

const operations = {
  hello() {
    return {
      protocol: 1,
      node: process.version,
      target: {
        checkout,
        commit: targetRevision(checkout),
        files: Object.fromEntries(TARGET_FILES.map((name) =>
          [name, sha256(fs.readFileSync(path.join(targetDir, name))).toString('hex')]))
      },
      keys: { ...XONLY, stateSignerKeyId: SIGNER_KEY_ID },
      defaults: {
        maxStateAgeBlocks: v2.DEFAULT_MAX_STATE_AGE_BLOCKS,
        challengeCsvBlocks: v2.DEFAULT_CHALLENGE_CSV_BLOCKS,
        recoveryCsvBlocks: v2.DEFAULT_RECOVERY_CSV_BLOCKS,
        minChallengeCsvBlocks: graphs.MIN_CHALLENGE_CSV_BLOCKS,
        minPayoutSats: v2.MIN_PAYOUT_SATS.toString()
      }
    };
  },

  // Signed state checkpoint, public trace and assertion template for one epoch.
  setup(p) {
    const contractId = sha256(`${DOMAIN}contract/${p.contract}`).toString('hex');
    const body = {
      network: p.network,
      chainGenesisHash: p.genesisHash,
      contractId,
      epochId: String(p.epochId),
      snapshotHeight: p.snapshotHeight,
      snapshotBlockHash: p.snapshotBlockHash,
      settlementAddressMap: {
        A: { address: 'payee-a', scriptPubKeyHex: p.payees.A },
        C: { address: 'payee-c', scriptPubKeyHex: p.payees.C }
      },
      pnlRows: [
        {
          id: 'a-wins-from-b', contractId, side: 'long', entryPrice: 2100, closePrice: 2200,
          quantityUnits: p.quantities.A, collateralSats: 50000, traderAddress: 'A', counterpartyAddress: 'B'
        },
        {
          id: 'c-wins-from-b', contractId, side: 'long', entryPrice: 2100, closePrice: 2200,
          quantityUnits: p.quantities.C, collateralSats: 50000, traderAddress: 'C', counterpartyAddress: 'B'
        }
      ]
    };
    const stateEnvelope = v2.buildSignedStateCheckpointV2(body, { privateKey: SIGNER_PRIVATE, publicKey: SIGNER_PUBLIC });
    const binding = graphs.buildSettlementTraceBindingV2({ stateEnvelope, feeSats: String(p.feeSats) });
    const wireBundle = traces.buildWireSecretSetV2([IN_STATE, IN_PAYOUT, OUT], { randomBytes: seededRandom(p.seed) });
    const publicTrace = traces.buildPublicTraceV2({
      circuitId: 'utxoref-settlement-and-v2',
      binding,
      gates: GATES,
      wireBundle,
      values: { [IN_STATE]: p.values[0], [IN_PAYOUT]: p.values[1], [OUT]: p.values[2] }
    });
    const template = graphs.buildBitvmAssertionTemplateV2({
      network: p.network,
      publicTrace,
      operatorXonly: XONLY.operator,
      challengerXonly: XONLY.challenger,
      challengeCsvBlocks: p.challengeCsvBlocks,
      recoveryCsvBlocks: p.recoveryCsvBlocks
    });
    contexts.set(p.ctx, {
      network: p.network, genesisHash: p.genesisHash, stateEnvelope, binding, wireBundle, publicTrace, template,
      graph: null
    });
    const derived = v2.derivePnlPayoutsV2(stateEnvelope.body);
    return {
      contractId,
      epochId: body.epochId,
      snapshotHeight: body.snapshotHeight,
      stateCheckpointHash: stateEnvelope.bodyHash,
      stateSignerKeyId: SIGNER_KEY_ID,
      binding,
      payouts: derived.payouts.map((payout) => ({ valueSats: payout.amountSats, scriptPubKeyHex: payout.scriptPubKeyHex })),
      amountSats: binding.assertionAmountSats,
      p2trScriptPubKey: template.p2trScriptPubKey,
      internalXonly: template.internalXonly,
      assertionTreeRoot: template.assertionTreeRoot,
      templateHash: template.templateHash,
      traceRoot: publicTrace.traceRoot,
      operatorXonly: template.operatorXonly,
      challengerXonly: template.challengerXonly,
      challengeCsvBlocks: template.challengeCsvBlocks,
      recoveryCsvBlocks: template.recoveryCsvBlocks,
      publicWires: publicTrace.publicWires,
      reveals: publicTrace.reveals,
      leaves: publicLeaves(template),
      templateCheck: graphs.verifyBitvmAssertionTemplateV2(template, publicTrace)
    };
  },

  // The whole graph, signed by the target's local ceremony, on the funded outpoint.
  graph(p) {
    const ctx = context(p.ctx);
    const stateVerification = verification(ctx, p.verification);
    const graph = graphs.finalizeBitvmAssertionGraphV2({
      template: ctx.template,
      publicTrace: ctx.publicTrace,
      stateEnvelope: ctx.stateEnvelope,
      stateVerification,
      assertionOutpoint: {
        txid: p.outpoint.txid,
        vout: p.outpoint.vout,
        amountSats: String(p.outpoint.amountSats),
        scriptPubKeyHex: p.outpoint.scriptPubKeyHex
      },
      feeSats: ctx.binding.feeSats,
      recoveryFeeSats: String(p.recoveryFeeSats),
      recoveryScriptPubKeyHex: p.recoveryScriptPubKeyHex,
      operatorSecret: SECRETS.operator,
      challengerSecret: SECRETS.challenger,
      operatorAux: aux('operator-settlement'),
      challengerAux: aux('challenger-settlement'),
      recoveryAux: aux('operator-recovery')
    });
    ctx.graph = graph;
    ctx.signingVerification = p.verification || {};
    return {
      graphHash: graph.graphHash,
      assertionOutpoint: graph.assertionOutpoint,
      commitmentCore: graph.settlement.commitment.core,
      settlementWitnessTxHex: graph.settlementPath.witnessTxHex,
      recoveryWitnessTxHex: graph.recoveryPath.witnessTxHex,
      recoveryScriptPubKeyHex: graph.recoveryPath.recoveryScriptPubKeyHex,
      recoveryFeeSats: graph.recoveryPath.recoveryFeeSats,
      challengerSettlementSignature: graph.settlementPath.challengerSignature,
      settlement: graph.settlement,
      verify: graphs.verifyBitvmAssertionGraphV2(graph, stateVerification)
    };
  },

  // The target's own disprove builder and verifier.
  disprove(p) {
    const ctx = context(p.ctx);
    const stateVerification = verification(ctx, p.verification === undefined ? ctx.signingVerification : p.verification);
    let disprove;
    try {
      disprove = graphs.buildBitvmDisproveV2(ctx.graph, {
        stateVerification,
        fraudType: p.fraudType,
        challengerSecret: SECRETS.challenger,
        challengerAux: aux('challenger-disprove'),
        feeSats: String(p.feeSats),
        challengeScriptPubKeyHex: p.challengeScriptPubKeyHex
      });
    } catch (err) {
      return { built: false, reason: err.message };
    }
    return {
      built: true,
      fraudType: disprove.fraudType,
      leafId: disprove.leafId,
      feeSats: disprove.feeSats,
      challengeScriptPubKeyHex: disprove.challengeScriptPubKeyHex,
      witnessTxHex: disprove.witnessTxHex,
      verify: graphs.verifyBitvmDisproveV2(ctx.graph, disprove, stateVerification)
    };
  },

  // A script-path spend of any committed leaf, assembled from the target's primitives:
  // witness = [signatures of `signers` in order, ...stackItems, leaf script, control block].
  leaf_spend(p) {
    const ctx = context(p.ctx);
    const leaf = leafOf(ctx.template, p.leafId);
    const outpoint = ctx.graph.assertionOutpoint;
    const unsignedTxHex = tr.serializeUnsignedTx(2, [{
      outpoint: tr.outpoint(outpoint.txid, outpoint.vout),
      sequence: p.sequence
    }], p.outputs.map((output) => ({ valueSats: BigInt(output.valueSats), script: output.scriptPubKeyHex })), 0);
    const sighash = ts.scriptPathSighash(
      v2.strictUnsignedTx(unsignedTxHex),
      [{ amountSats: outpoint.amountSats, scriptPubKey: outpoint.scriptPubKeyHex }],
      0,
      Buffer.from(leaf.leafHash, 'hex')
    );
    const signatures = p.signers.map((role) =>
      a.schnorrSign(BigInt(`0x${SECRETS[role]}`), sighash, aux(`leaf-spend/${role}`)).toString('hex'));
    const witness = [...signatures, ...(p.stackItems || []), leaf.scriptHex, leaf.controlBlock];
    const parsed = v2.strictUnsignedTx(unsignedTxHex);
    return {
      leafId: leaf.id,
      leafKind: leaf.kind,
      signers: p.signers,
      witnessTxHex: tr.serializeWitnessTx(
        parsed.version,
        parsed.vin.map((vin) => ({ outpoint: vin.outpoint.toString('hex'), sequence: vin.sequence, witness })),
        parsed.vout.map((output) => ({ valueSats: output.value, script: output.script.toString('hex') })),
        parsed.locktime
      )
    };
  },

  // The operator's own wire secret for the bit it did not reveal (models a leak to the challenger).
  leak_preimage(p) {
    const secret = context(p.ctx).wireBundle.secretWires[p.label];
    if (!secret) throw new Error(`unknown wire ${p.label}`);
    return { label: p.label, bit: p.bit, preimage: p.bit === 1 ? secret.preimage1 : secret.preimage0 };
  },

  // The operator alone builds a second graph on the same outpoint with another recovery
  // destination and fee. The challenger's settlement signature is copied from the first
  // graph and relabelled; the challenger's secret is not used.
  resign_recovery(p) {
    const ctx = context(p.ctx);
    const stateVerification = verification(ctx, ctx.signingVerification);
    const unsigned = graphs.buildUnsignedBitvmAssertionGraphV2({
      template: ctx.template,
      publicTrace: ctx.publicTrace,
      stateEnvelope: ctx.stateEnvelope,
      stateVerification,
      assertionOutpoint: ctx.graph.assertionOutpoint,
      feeSats: ctx.binding.feeSats,
      recoveryFeeSats: String(p.recoveryFeeSats),
      recoveryScriptPubKeyHex: p.recoveryScriptPubKeyHex
    });
    const relabelled = {
      kind: 'utxoref_bitvm_challenger_settlement_signature_v2',
      version: 2,
      unsignedGraphHash: unsigned.unsignedGraphHash,
      challengerXonly: ctx.template.challengerXonly,
      sighash: unsigned.settlementPath.sighash,
      signature: ctx.graph.settlementPath.challengerSignature
    };
    const second = graphs.operatorSignBitvmAssertionGraphV2(unsigned, relabelled, {
      stateVerification,
      operatorSecret: SECRETS.operator,
      operatorAux: aux('operator-settlement'),
      recoveryAux: aux('operator-recovery-resigned')
    });
    return {
      graphHash: second.graphHash,
      firstGraphHash: ctx.graph.graphHash,
      challengerSecretUsed: false,
      challengerSignatureReused: second.settlementPath.challengerSignature === ctx.graph.settlementPath.challengerSignature,
      settlementTxUnchanged: second.settlementPath.witnessTxHex === ctx.graph.settlementPath.witnessTxHex,
      recoveryScriptPubKeyHex: second.recoveryPath.recoveryScriptPubKeyHex,
      recoveryFeeSats: second.recoveryPath.recoveryFeeSats,
      recoveryWitnessTxHex: second.recoveryPath.witnessTxHex,
      verify: graphs.verifyBitvmAssertionGraphV2(second, stateVerification)
    };
  },

  // A settlement object for the context's signed state whose commitment names whatever the
  // caller chooses. Fields left out keep the honest graph's values.
  forge_settlement(p) {
    const ctx = context(p.ctx);
    const honest = ctx.graph.settlement.commitment.core;
    const feeSats = BigInt(p.feeSats ?? honest.feeSats);
    const challengeCsvBlocks = p.challengeCsvBlocks ?? honest.challengeCsvBlocks;
    const funding = p.funding
      ? { ...p.funding, amountSats: (BigInt(ctx.binding.payoutTotalSats) + feeSats).toString() }
      : ctx.graph.assertionOutpoint;
    const settlement = v2.buildUtxoRefPnlSettlementV2({
      stateEnvelope: ctx.stateEnvelope,
      stateVerification: verification(ctx, {}),
      fundingOutpoints: [funding],
      feeSats: feeSats.toString(),
      traceRoot: p.traceRoot ?? honest.traceRoot,
      assertionTreeRoot: p.assertionTreeRoot ?? honest.assertionTreeRoot,
      challengeCsvBlocks,
      recoveryCsvBlocks: p.recoveryCsvBlocks ?? honest.recoveryCsvBlocks,
      operatorXonly: p.operatorXonly ?? honest.operatorXonly,
      challengerXonly: p.challengerXonly ?? honest.challengerXonly
    });
    settlement.unsignedTxHex = tr.serializeUnsignedTx(2, [{
      outpoint: tr.outpoint(funding.txid, funding.vout),
      sequence: challengeCsvBlocks
    }], settlement.outputs.map((output) => ({ valueSats: output.valueSats, script: output.scriptPubKeyHex })), 0);
    return { settlement, honestCommitmentCore: honest };
  },

  // The target's settlement verifier on a caller-supplied object and trust options.
  verify_settlement(p) {
    return v2.verifyUtxoRefSettlementV2(p.settlement, verification(context(p.ctx), p.verification));
  },

  // The target's graph verifier on the context's graph, optionally with its settlement
  // replaced by a caller-supplied object (graph hash recomputed, as a forger would).
  verify_graph(p) {
    const ctx = context(p.ctx);
    const graph = JSON.parse(JSON.stringify(ctx.graph));
    if (p.settlement) {
      graph.settlement = p.settlement;
      graph.graphHash = graphs.computeBitvmAssertionGraphHashV2(graph);
    }
    return graphs.verifyBitvmAssertionGraphV2(graph, verification(ctx, p.verification));
  }
};

function encode(value) {
  return JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? item.toString() : item));
}

readline.createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', (line) => {
  if (!line.trim()) return;
  let request = {};
  try {
    request = JSON.parse(line);
    const operation = operations[request.op];
    if (!operation) throw new Error(`unknown operation ${request.op}`);
    process.stdout.write(`${encode({ id: request.id, ok: true, result: operation(request.params || {}) })}\n`);
  } catch (err) {
    process.stdout.write(`${encode({ id: request.id ?? null, ok: false, error: String(err && err.message || err) })}\n`);
  }
});
