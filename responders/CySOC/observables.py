#!/usr/bin/env python3
# encoding: utf-8
"""Shared observable/taxonomy helpers and canonical host (device) resolution.

These are responder-agnostic: both the DCSync responder (``whitelist.py`` —
user+host pairing) and the malware responder (``malware_respond.py`` — host +
hash/MISP) read canonical Microsoft Defender device ids from the enrichment
analyzer reports attached to case observables the same way. The DCSync-specific
Consul whitelist and user pairing stay in ``whitelist.py``.

Canonical ids come exclusively from the analyzer reports. A selected
non-destination observable that is neither resolved nor ``MDE:Not_Found`` is
returned as *unresolved* — callers fail the job on that (fail-safe: never act on
incomplete enrichment). An ``MDE:Not_Found`` observable is ignored.
"""
from typing import Optional

HOST_DATA_TYPES = ("hostname", "ip", "fqdn")

# Taxonomy predicate produced by the MicrosoftDefender device enrichment analyzer
DEVICE_ID_PREDICATES = ("Device_ID",)

# Observables created by enrichment analyzers carry this tag; they are
# by-products of the investigation, not the original alert host/account.
ARTIFACT_TAG_PREFIX = "MicrosoftDefender"

# Role tags attached by SOAR (StackStorm) from the Defender alert evidence roles
# (tag spelling "MDE:Role=<role>"; compared lower-cased). They identify the
# destination of a replication request — the attacked DC — which must never
# enter a whitelist pair. Untagged observables are treated as source.
ROLE_TAG_PREFIX = "mde:role="
ROLE_TAG_DESTINATION = "mde:role=destination"

# Mini-report taxonomy emitted by the MicrosoftDefender analyzers marking an
# observable that was looked up but is absent from MDE. Its value is null, so it
# is detected by predicate presence (taxonomy_value can't see a null value). The
# tag spelling is tolerated too, in case the chip is mirrored as an observable tag.
MDE_NAMESPACE = "MDE"
NOT_FOUND_PREDICATE = "Not_Found"
NOT_FOUND_TAG = "mde:not_found"


def select_candidates(observables: list, data_types: tuple, ignore_tag_prefix: str = ARTIFACT_TAG_PREFIX) -> list:
    return [
        obs
        for obs in observables
        if obs.get("dataType") in data_types
        and not any(tag.startswith(ignore_tag_prefix) for tag in obs.get("tags", []))
    ]


def taxonomy_value(observable: dict, predicates: tuple) -> Optional[str]:
    """Extract a taxonomy value from the observable's analyzer reports, honoring predicate priority."""
    for predicate in predicates:
        for report in (observable.get("reports") or {}).values():
            for taxonomy in report.get("taxonomies") or []:
                if taxonomy.get("predicate") == predicate and taxonomy.get("value"):
                    return str(taxonomy["value"])
    return None


def first_taxonomy_match(observable: dict, predicates: tuple) -> tuple:
    """Like taxonomy_value, but also returns which predicate matched (priority order)."""
    for predicate in predicates:
        value = taxonomy_value(observable, (predicate,))
        if value:
            return predicate, value
    return None, None


def is_destination(observable: dict) -> bool:
    """True if the observable is explicitly tagged as the replication destination (attacked DC)."""
    return any(tag.lower() == ROLE_TAG_DESTINATION for tag in observable.get("tags", []))


def has_role_tags(candidates: list) -> bool:
    """True if any candidate carries an mde:role= tag (in either source or destination form)."""
    return any(tag.lower().startswith(ROLE_TAG_PREFIX) for obs in candidates for tag in obs.get("tags", []))


def is_mde_not_found(observable: dict) -> bool:
    """True if the observable was looked up by MDE but is absent (MDE:Not_Found).

    The Not_Found taxonomy carries a null value, so it's detected by predicate presence rather than
    taxonomy_value (which requires a truthy value). An observable-tag spelling is honored too.
    """
    for report in (observable.get("reports") or {}).values():
        for taxonomy in report.get("taxonomies") or []:
            if taxonomy.get("namespace") == MDE_NAMESPACE and taxonomy.get("predicate") == NOT_FOUND_PREDICATE:
                return True
    return any(tag.lower().replace(" ", "") == NOT_FOUND_TAG for tag in observable.get("tags", []))


def resolve_candidates(
    candidates: list,
    predicates: tuple,
    unresolved: list,
    extra_ids: dict = None,
    display_predicates: tuple = None,
) -> list:
    """Resolve candidate observables to canonical-id entries, excluding destination identities.

    Two passes: the first collects the canonical ids of destination-tagged observables (which never
    need enrichment and are never sources); the second resolves the remaining observables and drops
    any whose canonical id matched a destination — so a destination DC tagged only on its hostname
    also excludes its untagged, same-machine ip. Entries are deduplicated on the canonical id.

    Each returned entry is {"data", "id", "id_predicate"} (+ any extra_ids fields). When
    display_predicates is given, "data" (the human-readable label) is taken from the first matching
    enrichment taxonomy (e.g. UPN, then Display_Name), falling back to the observable's own data.

    Selected non-destination observables without a canonical id are appended to ``unresolved``
    (unless they are MDE:Not_Found, which are skipped), so the caller can fail the job — fail-safe.
    """
    destination_ids = set()
    sources = []  # (obs, data, matched_predicate, canonical) for non-destination candidates
    for obs in candidates:
        data = (obs.get("data") or "").strip()
        matched_predicate, canonical = first_taxonomy_match(obs, predicates)
        if is_destination(obs):
            if canonical:
                destination_ids.add(canonical.lower())
            continue
        sources.append((obs, data, matched_predicate, canonical))

    resolved = []
    seen_ids = set()
    for obs, data, matched_predicate, canonical in sources:
        if canonical:
            canonical_id = canonical.lower()
            if canonical_id in destination_ids:
                continue  # same device/user as a destination-tagged observable
            if canonical_id not in seen_ids:
                seen_ids.add(canonical_id)
                display = taxonomy_value(obs, display_predicates) if display_predicates else None
                entry = {"data": display or data, "id": canonical, "id_predicate": matched_predicate}
                for field, field_predicates in (extra_ids or {}).items():
                    entry[field] = taxonomy_value(obs, field_predicates)
                resolved.append(entry)
        elif is_mde_not_found(obs):
            continue  # looked up by MDE but absent — ignore, don't block the job
        else:
            unresolved.append(
                {
                    "data": data,
                    "dataType": obs.get("dataType", ""),
                    "reason": "no MDE enrichment report — run the MicrosoftDefender analyzer "
                    "(Not_Found observables are skipped, not unresolved)",
                }
            )
    return resolved


def resolve_hosts(observables: list) -> tuple:
    """Resolve case observables to canonical devices.

    Returns (devices, unresolved). Each device is {"data": <host label>, "id": <Device_ID>,
    "id_predicate": "Device_ID"}; duplicates collapse on the canonical Device_ID, so the same
    machine seen as hostname, ip and fqdn yields one device. ``unresolved`` holds host observables
    present but not enriched (caller fails the job — fail-safe).
    """
    unresolved = []
    host_candidates = select_candidates(observables, HOST_DATA_TYPES)
    devices = resolve_candidates(host_candidates, DEVICE_ID_PREDICATES, unresolved)
    return devices, unresolved
