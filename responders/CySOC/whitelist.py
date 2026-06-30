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

The generic observable/taxonomy helpers and host (device) resolution live in
``observables.py`` and are shared with the malware responder; they are
re-exported here for backwards compatibility.
"""
import base64
from typing import Optional

import requests
import yaml

from observables import (
    HOST_DATA_TYPES,
    has_role_tags,
    is_destination,
    is_mde_not_found,
    resolve_candidates,
    resolve_devices,
    resolve_hosts,
    select_candidates,
    taxonomy_value,
)

USER_DATA_TYPES = ("username", "mail")

# Taxonomy predicates produced by the MicrosoftDefender user enrichment analyzer
USER_ID_PREDICATES = ("Account_Object_ID", "OnPrem_Object_ID")
# Supplementary user ids carried alongside the canonical user id, so containment can pick the right
# Graph/Defender action per identity type (Entra cloud-only vs on-prem/hybrid AD password reset).
ENTRA_OBJECT_ID_PREDICATES = ("Account_Object_ID",)
ONPREM_OBJECT_ID_PREDICATES = ("OnPrem_Object_ID",)
IDENTITY_ACCOUNT_ID_PREDICATES = ("Identity_Account_ID",)
# Human-readable user labels emitted by the GetUserInfo analyzer, preferred (in this order) over the
# raw observable text for display/metadata — so a user observable spelled as an Entra object-id GUID
# is still labelled with its UPN instead of the GUID. Matching is unaffected (it uses the canonical id).
USER_DISPLAY_PREDICATES = ("UPN", "Display_Name")

# Re-exported generic helpers — kept here so existing imports `from whitelist import ...` keep working.
__all__ = [
    "ConsulKVError",
    "ConsulWhitelist",
    "PairResolver",
    "pair_key",
    "select_candidates",
    "taxonomy_value",
    "is_destination",
    "has_role_tags",
    "is_mde_not_found",
    "resolve_devices",
    "resolve_hosts",
]


def pair_key(user_id: str, device_id: str) -> str:
    return f"{user_id.strip().lower()}:{device_id.strip().lower()}"


class ConsulKVError(Exception):
    """Raised when Consul KV cannot be read or written."""


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
        hosts = resolve_devices(host_candidates, unresolved)
        users = resolve_candidates(
            user_candidates,
            USER_ID_PREDICATES,
            unresolved,
            extra_ids={
                "entra_object_id": ENTRA_OBJECT_ID_PREDICATES,
                "onprem_object_id": ONPREM_OBJECT_ID_PREDICATES,
                "identity_account_id": IDENTITY_ACCOUNT_ID_PREDICATES,
            },
            display_predicates=USER_DISPLAY_PREDICATES,
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
