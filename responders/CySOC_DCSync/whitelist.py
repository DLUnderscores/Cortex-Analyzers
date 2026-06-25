#!/usr/bin/env python3
# encoding: utf-8
"""Whitelist storage (Consul KV) and canonical user+host pair resolution.

The whole whitelist lives in a single Consul KV key, as a YAML document
mapping pair key -> metadata:

    <account_object_id>:<device_id>:
      account: ...
      hostname: ...
      ...

The pair key alone decides a match; the rest only carries human-readable
metadata (who whitelisted what and why). Using directory object ids and MDE
device ids makes every spelling of the same user/host (SAM name, UPN, mail,
short hostname, FQDN, IP) map to the same entry. Writes are merged into the
document with Consul check-and-set (cas=<ModifyIndex>) and retried on
conflict, since the document is now a single resource shared by every write.
"""
import base64
from typing import Optional

import requests
import yaml

HOST_DATA_TYPES = ("hostname", "ip")
USER_DATA_TYPES = ("username", "mail")

# Taxonomy predicates produced by the MicrosoftDefender enrichment analyzers
DEVICE_ID_PREDICATES = ("Device_ID",)
USER_ID_PREDICATES = ("Account_Object_ID", "OnPrem_Object_ID")
# Supplementary user ids carried alongside the canonical user id, so containment can pick the right
# Graph/Defender action per identity type (Entra cloud-only vs on-prem/hybrid AD password reset).
ENTRA_OBJECT_ID_PREDICATES = ("Account_Object_ID",)
ONPREM_OBJECT_ID_PREDICATES = ("OnPrem_Object_ID",)
IDENTITY_ACCOUNT_ID_PREDICATES = ("Identity_Account_ID",)

# Observables created by enrichment analyzers carry this tag; they are
# by-products of the investigation, not the DCSync source host/account.
ARTIFACT_TAG_PREFIX = "MicrosoftDefender"

# Role tags attached by SOAR (StackStorm) from the Defender alert evidence roles
# (tag spelling "MDE:Role=<role>"; compared lower-cased). They identify the
# destination of the replication request — the attacked DC — which must never
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


class ConsulKVError(Exception):
    """Raised when Consul KV cannot be read or written."""


def pair_key(user_id: str, device_id: str) -> str:
    return f"{user_id.strip().lower()}:{device_id.strip().lower()}"


class ConsulWhitelist:
    MAX_CAS_ATTEMPTS = 5

    def __init__(self, url: str, key: str, token: Optional[str] = None, http=requests):
        self.url = url.rstrip("/")
        self.key = key.strip("/")
        self.http = http
        self.headers = {"X-Consul-Token": token} if token else {}

    def _read(self) -> tuple:
        """Return (entries, modify_index); modify_index is None when the key doesn't exist yet."""
        resp = self.http.get(f"{self.url}/v1/kv/{self.key}", headers=self.headers, timeout=30)
        if resp.status_code == 404:
            return {}, None
        if not (200 <= resp.status_code < 300):
            raise ConsulKVError(f"Failed to read whitelist at {self.key}: HTTP {resp.status_code} — {resp.text}")
        item = (resp.json() or [{}])[0]
        value = item.get("Value")
        entries = yaml.safe_load(base64.b64decode(value)) if value else None
        return entries or {}, item.get("ModifyIndex")

    def entries(self) -> dict:
        """Return all whitelist entries as {pair_key: metadata}."""
        return self._read()[0]

    def _cas_update(self, mutate) -> None:
        for _ in range(self.MAX_CAS_ATTEMPTS):
            entries, index = self._read()
            mutate(entries)
            body = yaml.safe_dump(entries, default_flow_style=False, sort_keys=True, indent=2)
            resp = self.http.put(
                f"{self.url}/v1/kv/{self.key}",
                params={"cas": index or 0},
                data=body.encode("utf-8"),
                headers=self.headers,
                timeout=30,
            )
            if not (200 <= resp.status_code < 300):
                raise ConsulKVError(f"Failed to write whitelist at {self.key}: HTTP {resp.status_code} — {resp.text}")
            if resp.json() is True:
                return
        raise ConsulKVError(f"Failed to write whitelist at {self.key} after {self.MAX_CAS_ATTEMPTS} attempts — concurrent update")

    def put(self, key: str, metadata: dict) -> None:
        self._cas_update(lambda entries: entries.__setitem__(key, metadata))


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


class PairResolver:
    """Resolve case observables to canonical (user, host) pairs.

    Role tags (set by SOAR from the Defender evidence) exclude the replication
    destination — the attacked DC — from pairing. Exclusion is by canonical id,
    not per-observable: if any observable resolving to a given Device_ID/user id
    is tagged mde:role=destination, every observable for that identity is dropped
    (so a destination DC tagged only on its hostname still excludes its untagged,
    same-machine ip). Untagged observables are treated as source.

    An observable that MDE looked up but couldn't find (MDE:Not_Found) is ignored.
    Canonical ids are read exclusively from the enrichment analyzer reports; a
    selected non-destination observable that is neither resolved nor Not_Found is
    returned as unresolved (the caller fails the job — fail-safe).
    """

    def resolve(self, observables: list) -> tuple:
        """Return (pairs, unresolved, selection).

        pairs:      [{"key", "user", "user_id", "user_id_predicate", "entra_object_id",
                    "onprem_object_id", "identity_account_id", "host", "device_id"}]
                    — user×host combinations. "user_id_predicate" records which taxonomy
                    matched the canonical user id (e.g. "Account_Object_ID" vs "OnPrem_Object_ID"),
                    since only the former is a Microsoft Graph-recognized id. The three id fields
                    carry the individual ids (any may be None) so containment can pick the right
                    action per identity type — Entra cloud-only vs on-prem/hybrid AD reset.
        unresolved: [{"data", "dataType", "reason"}] — selected candidates without a canonical id
        selection:  "source-role-tags" when role tags narrowed any group, else "all-candidates"
        """
        unresolved = []
        host_candidates = select_candidates(observables, HOST_DATA_TYPES)
        user_candidates = select_candidates(observables, USER_DATA_TYPES)
        role_tags_used = has_role_tags(host_candidates) or has_role_tags(user_candidates)
        hosts = self._resolve_candidates(host_candidates, DEVICE_ID_PREDICATES, unresolved)
        users = self._resolve_candidates(
            user_candidates,
            USER_ID_PREDICATES,
            unresolved,
            extra_ids={
                "entra_object_id": ENTRA_OBJECT_ID_PREDICATES,
                "onprem_object_id": ONPREM_OBJECT_ID_PREDICATES,
                "identity_account_id": IDENTITY_ACCOUNT_ID_PREDICATES,
            },
        )

        pairs = [
            {
                "key": pair_key(user["id"], host["id"]),
                "user": user["data"],
                "user_id": user["id"],
                "user_id_predicate": user["id_predicate"],
                "entra_object_id": user.get("entra_object_id"),
                "onprem_object_id": user.get("onprem_object_id"),
                "identity_account_id": user.get("identity_account_id"),
                "host": host["data"],
                "device_id": host["id"],
            }
            for user in users
            for host in hosts
        ]
        selection = "source-role-tags" if role_tags_used else "all-candidates"
        return pairs, unresolved, selection

    def _resolve_candidates(self, candidates: list, predicates: tuple, unresolved: list, extra_ids: dict = None) -> list:
        """Resolve candidates to canonical-id entries, excluding destination identities.

        Two passes: the first collects the canonical ids of destination-tagged observables (which never
        need enrichment and are never sources); the second resolves the remaining observables and drops
        any whose canonical id matched a destination — so a destination DC tagged only on its hostname
        also excludes its untagged, same-machine ip.
        """
        destination_ids = set()
        sources = []  # (obs, data, matched_predicate, canonical) for non-destination candidates
        for obs in candidates:
            data = (obs.get("data") or "").strip()
            matched_predicate, canonical = self._first_taxonomy_match(obs, predicates)
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
                    entry = {"data": data, "id": canonical, "id_predicate": matched_predicate}
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

    @staticmethod
    def _first_taxonomy_match(observable: dict, predicates: tuple) -> tuple:
        """Like taxonomy_value, but also returns which predicate matched (priority order)."""
        for predicate in predicates:
            value = taxonomy_value(observable, (predicate,))
            if value:
                return predicate, value
        return None, None
