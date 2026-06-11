#!/usr/bin/env python3
# encoding: utf-8
"""Whitelist storage (Consul KV) and canonical user+host pair resolution.

A whitelist entry is one Consul KV key under a per-tenant prefix:

    <prefix>/<account_object_id>:<device_id>

The key alone decides a match; the JSON value only carries human-readable
metadata (who whitelisted what and why). Using directory object ids and MDE
device ids makes every spelling of the same user/host (SAM name, UPN, mail,
short hostname, FQDN, IP) map to the same entry.
"""
import base64
import json
from typing import Optional

import requests

HOST_DATA_TYPES = ("hostname", "fqdn")
USER_DATA_TYPES = ("username", "mail")

# Taxonomy predicates produced by the MicrosoftDefender enrichment analyzers
DEVICE_ID_PREDICATES = ("Device_ID",)
USER_ID_PREDICATES = ("Account_Object_ID", "OnPrem_Object_ID")

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
    def __init__(self, url: str, prefix: str, token: Optional[str] = None, http=requests):
        self.url = url.rstrip("/")
        self.prefix = prefix.strip("/")
        self.http = http
        self.headers = {"X-Consul-Token": token} if token else {}

    def entries(self) -> dict:
        """Return all whitelist entries as {pair_key: metadata}."""
        resp = self.http.get(
            f"{self.url}/v1/kv/{self.prefix}",
            params={"recurse": "true"},
            headers=self.headers,
            timeout=30,
        )
        if resp.status_code == 404:
            return {}
        if not (200 <= resp.status_code < 300):
            raise ConsulKVError(f"Failed to read whitelist at {self.prefix}: HTTP {resp.status_code} — {resp.text}")
        entries = {}
        for item in resp.json() or []:
            key = item.get("Key", "")[len(self.prefix) :].strip("/")
            if not key:
                continue
            value = item.get("Value")
            metadata = {}
            if value:
                try:
                    metadata = json.loads(base64.b64decode(value))
                except (ValueError, TypeError):
                    metadata = {"raw": base64.b64decode(value).decode("utf-8", errors="replace")}
            entries[key] = metadata
        return entries

    def put(self, key: str, metadata: dict) -> None:
        resp = self.http.put(
            f"{self.url}/v1/kv/{self.prefix}/{key}",
            data=json.dumps(metadata, ensure_ascii=False).encode("utf-8"),
            headers=self.headers,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise ConsulKVError(f"Failed to write whitelist entry {key}: HTTP {resp.status_code} — {resp.text}")


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

        pairs:      [{"key", "user", "user_id", "host", "device_id"}] — user×host combinations
        unresolved: [{"data", "dataType", "reason"}] — selected candidates without a canonical id
        selection:  "source-role-tags" when role tags narrowed any group, else "all-candidates"
        """
        unresolved = []
        host_candidates, hosts_by_role = select_source_candidates(select_candidates(observables, HOST_DATA_TYPES))
        user_candidates, users_by_role = select_source_candidates(select_candidates(observables, USER_DATA_TYPES))
        hosts = self._resolve_candidates(host_candidates, DEVICE_ID_PREDICATES, unresolved)
        users = self._resolve_candidates(user_candidates, USER_ID_PREDICATES, unresolved)

        pairs = [
            {
                "key": pair_key(user["id"], host["id"]),
                "user": user["data"],
                "user_id": user["id"],
                "host": host["data"],
                "device_id": host["id"],
            }
            for user in users
            for host in hosts
        ]
        selection = "source-role-tags" if (hosts_by_role or users_by_role) else "all-candidates"
        return pairs, unresolved, selection

    def _resolve_candidates(self, candidates: list, predicates: tuple, unresolved: list) -> list:
        resolved = []
        seen_ids = set()
        for obs in candidates:
            data = (obs.get("data") or "").strip()
            canonical = taxonomy_value(obs, predicates)
            if canonical:
                if canonical.lower() not in seen_ids:
                    seen_ids.add(canonical.lower())
                    resolved.append({"data": data, "id": canonical})
            else:
                unresolved.append(
                    {
                        "data": data,
                        "dataType": obs.get("dataType", ""),
                        "reason": "no enrichment report with a canonical id — run the MicrosoftDefender analyzers first",
                    }
                )
        return resolved
