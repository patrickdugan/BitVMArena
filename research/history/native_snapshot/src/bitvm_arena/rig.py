from __future__ import annotations

from dataclasses import dataclass

from .definitions import COMPONENTS, COMBINATIONS, CircuitCombination


@dataclass(frozen=True)
class RigProfile:
    rig_id: str
    label: str
    state_model: str
    execution_model: str
    commitment_surfaces: tuple[str, ...]
    witness_surfaces: tuple[str, ...]
    settlement_surfaces: tuple[str, ...]
    review_objective: str


def _component_labels(combination: CircuitCombination) -> set[str]:
    return set(combination.components)


def build_rig_profile(combination: CircuitCombination) -> RigProfile:
    components = _component_labels(combination)
    state_parts: list[str] = []
    commitment_surfaces: list[str] = []
    witness_surfaces: list[str] = []
    settlement_surfaces: list[str] = []

    if {"challenge_route_selector", "epoch_rollover_router", "receipt_rollover_router"} & components:
        state_parts.append("route-aware rollover state machine")
        commitment_surfaces.append("route selectors and epoch-local state vectors")
        witness_surfaces.append("route-specific witness branches")
        settlement_surfaces.append("rollover and retry windows")
    if {"payout_cap_limiter", "residual_destination_encoder", "u32_addition_chain"} & components:
        state_parts.append("bounded settlement and carry-forward ledger")
        commitment_surfaces.append("payout, refund, and residual accounting fields")
        witness_surfaces.append("width-sensitive arithmetic intermediates")
        settlement_surfaces.append("cap, refund, and carry-forward outputs")
    if {"transcript_commitment_bus", "identifier_namespace_anchor", "oracle_sidecar_commitment"} & components:
        state_parts.append("transcript and identifier overlay namespace")
        commitment_surfaces.append("transcript roots, anchor ids, and sidecar mirrors")
        witness_surfaces.append("relay aliases and anchor-derived ids")
        settlement_surfaces.append("publication and observer-visible carrier lanes")
    if {"tradelayer_state_oracle", "dlc_funder_registry", "sweep_rpc_preflight", "wallet_flow_model"} & components:
        state_parts.append("TradeLayer send-to-sweep route binding")
        commitment_surfaces.append("state-oracle hashes, registry hashes, route plan hashes, and wallet flow hashes")
        witness_surfaces.append("selected send rows, registry mappings, RPC preflight observations, and signed PSBT outputs")
        settlement_surfaces.append("DLC funding outputs, refund outputs, mempool acceptance, and sweep txids")
    if {
        "tradelayer_state_checkpoint",
        "tradelayer_withdrawal_queue",
        "tradelayer_perp_pnl_settlement",
        "bitvm_liquidity_lease",
        "final_sweep_output_binding",
        "dashboard_view_projection",
    } & components:
        state_parts.append("stack-wide TradeLayer BitVM referee bundle")
        commitment_surfaces.append(
            "checkpoint roots, withdrawal queue roots, PNL settlement hashes, lease evidence hashes, final output hashes, and dashboard view hashes"
        )
        witness_surfaces.append(
            "accepted txids, queue requests, PNL mark sources, route evidence observations, decoded final outputs, and dashboard action projections"
        )
        settlement_surfaces.append(
            "winner/refund outputs, liquidity premiums, challenge paths, dashboard alerts, and stack hash handoff artifacts"
        )
    if {"ark_taproot_miniscript_claim", "shinigami_cairo_vm_trace", "stwo_proof_receipt"} & components:
        state_parts.append("Shinigami ZK proof-carrying Ark statement")
        commitment_surfaces.append(
            "claim digests, proof transcript roots, public input manifests, proof-system ids, and verifier exit policies"
        )
        witness_surfaces.append(
            "Cairo execution traces, Taproot path folds, selected leaf roles, and settlement witnesses"
        )
        settlement_surfaces.append(
            "Ark Taproot miniscript claims, proof receipts, verifier receipts, and challengeable proof publications"
        )
    if {"virtual_cet_leaf_set", "oracle_sidecar_commitment"} & components:
        state_parts.append("virtual-CET Ark leaf and oracle outcome binding")
        commitment_surfaces.append(
            "virtual CET set roots, Ark leaf roots, selected leaf hashes, oracle outcome hashes, and payout roots"
        )
        witness_surfaces.append(
            "selected outcome evidence, membership paths, oracle attestation age, and payout recomputation inputs"
        )
        settlement_surfaces.append(
            "compressed DLC settlement roots, ASP forfeit routes, stale-oracle challenges, and virtual-leaf fraud cases"
        )
    if {"lightning_payment_condition_receipt", "programmable_watchtower_policy", "programmable_asp_policy"} & components:
        state_parts.append("Lightning-conditioned ZK policy sidecar")
        commitment_surfaces.append(
            "payment hashes, invoice hashes, context binding hashes, Ark ZK receipt roles, and state transition hashes"
        )
        witness_surfaces.append(
            "preimage witness commitments, route observations, fee and CLTV ceilings, delivered inbound sats, and receipt refs"
        )
        settlement_surfaces.append(
            "watchtower challenges, ASP slash or force-exit policies, liquidity release decisions, and privacy-bound receipts"
        )
    if {"merkleized_rom_reader", "merkleized_redemption_tree", "sha256_round_slice"} & components:
        state_parts.append("Merkle-committed execution trace")
        commitment_surfaces.append("Merkle roots, leaf indices, and hash slices")
        witness_surfaces.append("proof shapes, sibling order, and trace segments")
        settlement_surfaces.append("partial-vs-full redemption branches")
    if not state_parts:
        state_parts.append("compact BitVM commitment state machine")

    if {"lightning_payment_condition_receipt", "programmable_watchtower_policy", "programmable_asp_policy"} & components:
        execution_model = "payment-conditioned ZK policy sidecar with watchtower and ASP challenge actions"
    elif {"virtual_cet_leaf_set", "ark_taproot_miniscript_claim"} & components:
        execution_model = "compressed DLC virtual-CET proof bridge with Ark/BitVM challenge escalation"
    elif {"shinigami_cairo_vm_trace", "stwo_proof_receipt", "verifier_handle_publication"} & components:
        execution_model = "proof-carrying execution publication with verifier-handle challenge routing"
    elif {"ark_taproot_miniscript_claim", "shinigami_cairo_vm_trace"} & components:
        execution_model = "Cairo-verified Ark taproot claim with proof-receipt settlement handoff"
    elif {"tradelayer_state_checkpoint", "dashboard_view_projection", "bitvm_liquidity_lease"} & components:
        execution_model = "stack-wide cross-domain referee with dashboard-projected challenge surfaces"
    elif {"tradelayer_state_oracle", "sweep_rpc_preflight"} & components:
        execution_model = "cross-domain send route with RPC-gated sweep signing"
    elif {"bitwise_logic_mux", "challenge_route_selector"} & components:
        execution_model = "multi-lane execution with selector-driven branch choice"
    elif "fraud_proof_timeout_gate" in components:
        execution_model = "optimistic execution with timeout-gated dispute escalation"
    else:
        execution_model = "single-lane execution with committed state transitions"

    # Preserve insertion order while removing duplicates.
    def unique(items: list[str]) -> tuple[str, ...]:
        ordered: list[str] = []
        for item in items:
            if item not in ordered:
                ordered.append(item)
        return tuple(ordered)

    return RigProfile(
        rig_id=f"{combination.key}_rig",
        label=f"{combination.title} Rig",
        state_model="; ".join(state_parts),
        execution_model=execution_model,
        commitment_surfaces=unique(commitment_surfaces),
        witness_surfaces=unique(witness_surfaces),
        settlement_surfaces=unique(settlement_surfaces),
        review_objective=(
            "Verify that one economic claim, one route interpretation, and one witness layout "
            "remain bound to the same committed state under mutation pressure."
        ),
    )


def build_rig_catalog() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for combination in COMBINATIONS:
        profile = build_rig_profile(combination)
        rows.append(
            {
                "combination_id": combination.key,
                "combination_title": combination.title,
                "rig_id": profile.rig_id,
                "rig_label": profile.label,
                "state_model": profile.state_model,
                "execution_model": profile.execution_model,
                "commitment_surfaces": list(profile.commitment_surfaces),
                "witness_surfaces": list(profile.witness_surfaces),
                "settlement_surfaces": list(profile.settlement_surfaces),
                "review_objective": profile.review_objective,
                "components": [
                    {
                        "key": component_key,
                        "label": COMPONENTS[component_key].label,
                        "role": COMPONENTS[component_key].role,
                    }
                    for component_key in combination.components
                ],
            }
        )
    return rows
