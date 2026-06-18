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

HOST_DATA_TYPES = ("hostname",)
USER_DATA_TYPES = ("username",)

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

# Role tags attached during ES→TheHive ingestion from the Defender alert
# evidence; when present they identify the source of the replication request.
ROLE_TAG_PREFIX = "mde:role="
ROLE_TAG_SOURCE = "mde:role=source"


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


def select_source_candidates(candidates: list) -> tuple:
    """Restrict candidates to the attack source when role tags are present.

    Returns (candidates, role_tags_used). When any candidate carries an
    mde:role= tag, only candidates tagged as source are kept — the
    destination (e.g. the attacked domain controller) must never enter the
    whitelist pair. Without role tags all candidates are kept.
    """
    has_role_tags = any(
        tag.lower().startswith(ROLE_TAG_PREFIX) for obs in candidates for tag in obs.get("tags", [])
    )
    if not has_role_tags:
        return candidates, False
    return [obs for obs in candidates if any(tag.lower() == ROLE_TAG_SOURCE for tag in obs.get("tags", []))], True


class PairResolver:
    """Resolve case observables to canonical (user, host) pairs.

    When observables carry mde:role= tags (set during alert ingestion from
    the Defender evidence), only source-tagged candidates are paired.
    Canonical ids are read exclusively from the enrichment analyzer reports
    attached to the observables; a selected observable without a report
    cannot be resolved and is returned as unresolved (the caller fails the
    job).
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
        host_candidates, hosts_by_role = select_source_candidates(select_candidates(observables, HOST_DATA_TYPES))
        user_candidates, users_by_role = select_source_candidates(select_candidates(observables, USER_DATA_TYPES))
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
        selection = "source-role-tags" if (hosts_by_role or users_by_role) else "all-candidates"
        return pairs, unresolved, selection

    def _resolve_candidates(self, candidates: list, predicates: tuple, unresolved: list, extra_ids: dict = None) -> list:
        resolved = []
        seen_ids = set()
        for obs in candidates:
            data = (obs.get("data") or "").strip()
            matched_predicate, canonical = self._first_taxonomy_match(obs, predicates)
            if canonical:
                if canonical.lower() not in seen_ids:
                    seen_ids.add(canonical.lower())
                    entry = {"data": data, "id": canonical, "id_predicate": matched_predicate}
                    for field, field_predicates in (extra_ids or {}).items():
                        entry[field] = taxonomy_value(obs, field_predicates)
                    resolved.append(entry)
            else:
                unresolved.append(
                    {
                        "data": data,
                        "dataType": obs.get("dataType", ""),
                        "reason": "no enrichment report with a canonical id — run the MicrosoftDefender analyzers first",
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
