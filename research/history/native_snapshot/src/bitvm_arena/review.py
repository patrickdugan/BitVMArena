from __future__ import annotations

from dataclasses import dataclass

from .definitions import COMPONENTS, LOOPHOLES, CircuitCombination
from .mutations import MutationFamily, select_mutation_families
from .rig import RigProfile, build_rig_profile
from .wallet_preflight import WalletPreflightProfile, select_preflight_profile


@dataclass(frozen=True)
class ReviewDossier:
    rig_profile: RigProfile
    preflight_profile: WalletPreflightProfile
    mutations: tuple[MutationFamily, ...]
    review_questions: tuple[str, ...]
    review_checklist: tuple[str, ...]


def build_review_dossier(combination: CircuitCombination) -> ReviewDossier:
    rig_profile = build_rig_profile(combination)
    preflight_profile = select_preflight_profile(combination)
    mutations = select_mutation_families(combination)
    review_questions = tuple(mutation.review_question for mutation in mutations)
    review_checklist = (
        "First decide what a funding wallet should reject before money moves, then analyze what remains wallet-opaque.",
        "Name the dominant loophole for the exact rig variant in front of you, not just the broader protocol family.",
        "Explain how the committed economic claim could diverge from the route, witness layout, transcript, or settlement representation.",
        "Recommend controls that canonically bind byte layout, selector semantics, and settlement accounting for this rig.",
        preflight_profile.review_question,
        *[question for question in review_questions[:2]],
    )
    return ReviewDossier(
        rig_profile=rig_profile,
        preflight_profile=preflight_profile,
        mutations=mutations,
        review_questions=review_questions,
        review_checklist=review_checklist,
    )


def render_review_prompt(combination: CircuitCombination) -> str:
    dossier = build_review_dossier(combination)
    component_lines = [
        f"- {COMPONENTS[key].label}: {COMPONENTS[key].role}"
        for key in combination.components
    ]
    invariant_lines = [f"- {item}" for item in combination.invariants]
    loophole_labels = ", ".join(
        LOOPHOLES[key].label for key in combination.supported_loopholes
    )
    mutation_lines = [
        (
            f"- {mutation.label}: {mutation.description} "
            f"Canonical form: {mutation.canonical_form} "
            f"Adversarial variant: {mutation.adversarial_variant} "
            f"Binding invariant: {mutation.binding_invariant}"
        )
        for mutation in dossier.mutations
    ]
    preflight = dossier.preflight_profile
    preflight_detectable_lines = [f"- {item}" for item in preflight.detectable_failures]
    preflight_blind_spot_lines = [f"- {item}" for item in preflight.blind_spots]
    preflight_check_lines = [f"- {item}" for item in preflight.required_checks]
    preflight_binding_lines = [f"- {item}" for item in preflight.semantic_bindings]
    checklist_lines = [f"- {item}" for item in dossier.review_checklist]
    rig = dossier.rig_profile

    return "\n".join(
        [
            "Review the following BitVM circuit composition before sign-off.",
            "",
            f"Combination ID: {combination.key}",
            f"Scenario: {combination.scenario}",
            "",
            "Rig profile:",
            f"- Rig ID: {rig.rig_id}",
            f"- Rig label: {rig.label}",
            f"- State model: {rig.state_model}",
            f"- Execution model: {rig.execution_model}",
            f"- Review objective: {rig.review_objective}",
            "",
            "Funding wallet preflight:",
            f"- Preflight profile: {preflight.label}",
            "- Wallet-detectable failures:",
            *preflight_detectable_lines,
            "- Wallet blind spots:",
            *preflight_blind_spot_lines,
            "- Required pre-funding checks:",
            *preflight_check_lines,
            "- Required semantic bindings:",
            *preflight_binding_lines,
            f"- Red-team bypass pressure: {preflight.bypass_pressure}",
            "",
            "Components in scope:",
            *component_lines,
            "",
            "Security invariants:",
            *invariant_lines,
            "",
            "Mutation families in scope:",
            *mutation_lines,
            "",
            f"Common loophole families in scope: {loophole_labels}.",
            "",
            "Review checklist:",
            *checklist_lines,
            "",
            "Task:",
            "- Identify the dominant loophole for this composition.",
            "- Explain one concrete exploit path.",
            "- Recommend at least three concrete controls.",
            "- Use the submit tool with the requested structured audit fields.",
        ]
    )


def build_review_catalog(combinations: tuple[CircuitCombination, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for combination in combinations:
        dossier = build_review_dossier(combination)
        rows.append(
            {
                "combination_id": combination.key,
                "combination_title": combination.title,
                "prompt": render_review_prompt(combination),
                "rig_profile": {
                    "rig_id": dossier.rig_profile.rig_id,
                    "rig_label": dossier.rig_profile.label,
                    "state_model": dossier.rig_profile.state_model,
                    "execution_model": dossier.rig_profile.execution_model,
                    "commitment_surfaces": list(dossier.rig_profile.commitment_surfaces),
                    "witness_surfaces": list(dossier.rig_profile.witness_surfaces),
                    "settlement_surfaces": list(dossier.rig_profile.settlement_surfaces),
                    "review_objective": dossier.rig_profile.review_objective,
                },
                "wallet_preflight": {
                    "key": dossier.preflight_profile.key,
                    "label": dossier.preflight_profile.label,
                    "detectable_failures": list(dossier.preflight_profile.detectable_failures),
                    "blind_spots": list(dossier.preflight_profile.blind_spots),
                    "required_checks": list(dossier.preflight_profile.required_checks),
                    "semantic_bindings": list(dossier.preflight_profile.semantic_bindings),
                    "review_question": dossier.preflight_profile.review_question,
                    "bypass_pressure": dossier.preflight_profile.bypass_pressure,
                    "detection_terms": list(dossier.preflight_profile.detection_terms),
                },
                "mutations": [
                    {
                        "key": mutation.key,
                        "label": mutation.label,
                        "description": mutation.description,
                        "canonical_form": mutation.canonical_form,
                        "adversarial_variant": mutation.adversarial_variant,
                        "binding_invariant": mutation.binding_invariant,
                        "red_team_vector": mutation.red_team_vector,
                        "review_question": mutation.review_question,
                        "control_focus": list(mutation.control_focus),
                        "detection_terms": list(mutation.detection_terms),
                    }
                    for mutation in dossier.mutations
                ],
                "review_questions": list(dossier.review_questions),
                "review_checklist": list(dossier.review_checklist),
            }
        )
    return rows
