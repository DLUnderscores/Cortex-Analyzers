#!/usr/bin/env python3
# encoding: utf-8
"""Resolve a case's USM ticket template out of the ``case-reasoning.yml`` document in Consul KV.

Background: nothing from a ``case-reasoning.yml`` entry reaches a responder through Cortex.
The SOAR chain that starts case responders passes only ``{objectId, objectType, responderId}``
to TheHive's Cortex connector, so a responder that wants its own per-org/per-case-type
configuration has to go and read it. Both documents it needs are already published to Consul
KV by ``sirp/thehive-config/thehive-configure.yml``:

    cysoc/<tenant>/sirp/thehive/case-reasoning   {org: {case template: {response: {...}}}}
    cysoc/<tenant>/sirp/thehive/case-mappings    {org: {case template: [title needles]}}

The org selection and the title -> case-template matching here are deliberate ports of the
SOAR's own logic (``AlertsHelper.select_org_config`` and
``ThehiveMatchOpenCases._get_template``): both sides must land on the same entry for the same
case, otherwise a case would be *evaluated* under one template and *ticketed* under another.
Keep them in step if the SOAR versions change.
"""
import base64
import re

import requests
import yaml

# Top-level key holding the configuration used for every organisation without its own block.
# Mirrors AlertsHelper.DEFAULT_ORG_CONFIG_KEY in the SOAR pack.
DEFAULT_ORG_CONFIG_KEY = "_default_"


class CaseReasoningError(Exception):
    """Raised when a case-reasoning/case-mappings document cannot be read or parsed."""


def read_kv_yaml(url, key, token=None, http=requests):
    """Read a YAML document from Consul KV. Returns the parsed value, or None if the key is absent."""
    headers = {"X-Consul-Token": token} if token else {}
    resp = http.get(f"{url.rstrip('/')}/v1/kv/{key.strip('/')}", headers=headers, timeout=30)
    if resp.status_code == 404:
        return None
    if not (200 <= resp.status_code < 300):
        raise CaseReasoningError(f"Failed to read {key}: HTTP {resp.status_code} — {resp.text}")
    item = (resp.json() or [{}])[0]
    value = item.get("Value")
    if not value:
        return None
    try:
        return yaml.safe_load(base64.b64decode(value))
    except yaml.YAMLError as exc:
        raise CaseReasoningError(f"Failed to parse {key} as YAML: {exc}") from exc


def select_org_config(config, org):
    """Resolve the per-organisation block from a ``{_default_: ..., <org>: ...}`` document.

    A named org block *replaces* ``_default_`` wholesale — there is no merge, so an org with
    its own block must restate everything it needs. A document with no ``_default_`` key is
    returned unchanged (the pre-org flat layout). Port of AlertsHelper.select_org_config.
    """
    if not isinstance(config, dict) or DEFAULT_ORG_CONFIG_KEY not in config:
        return config or {}
    if org and org in config:
        return config[org] or {}
    return config.get(DEFAULT_ORG_CONFIG_KEY) or {}


def internal_ref_of(case):
    """Return the case's ``internal-ref`` custom field value, or None.

    Handles both renderings: the v1 query output is a list of ``{name, value}``; the v0 output
    Cortex is handed for a responder is ``{name: {typeName: value}}``.
    """
    cfs = (case or {}).get("customFields")
    if isinstance(cfs, list):
        for cf in cfs:
            if isinstance(cf, dict) and cf.get("name") == "internal-ref":
                return cf.get("value")
    elif isinstance(cfs, dict):
        entry = cfs.get("internal-ref")
        if isinstance(entry, dict):
            return entry.get("string") or entry.get("value")
        if isinstance(entry, str):
            return entry
    return None


def org_from_ref(ref):
    """Organisation prefix of a scoped internal-ref (``<org>:<ref>``), or None."""
    if not isinstance(ref, str) or ":" not in ref:
        return None
    return ref.split(":", 1)[0] or None


def org_of(case, fallback=None):
    """The organisation whose config block applies to this case.

    Primary source is the org-scoped ``internal-ref``, which is what the SOAR keys off — so a
    case evaluated under an org's block is ticketed under the same block. An alert created
    without a ``data_stream.namespace`` carries a bare ref with no org prefix; for those we
    fall back to the organisation TheHive injects into the responder's job parameters (the
    case's owning org), which the SOAR has no equivalent of.
    """
    return org_from_ref(internal_ref_of(case)) or fallback or None


def resolve_template_name(title, mappings):
    """Match a case title to a case-template name via the title needles in case-mappings.

    Port of ThehiveMatchOpenCases._get_template: ``(\\d+)`` groups (TheHive's duplicate-title
    counter) are stripped, then the first template with a case-insensitive substring hit wins.
    """
    if not isinstance(mappings, dict):
        return None
    needle_haystack = re.sub(r"\(\d+\)", "", title or "").strip().lower()
    for template, needles in mappings.items():
        if isinstance(needles, list) and any(str(n).lower() in needle_haystack for n in needles):
            return template
    return None


def find_response_entry(reasoning, template_name, responder_base_name):
    """The ``response:`` entry for this responder under ``template_name``, or None.

    Matched by prefix rather than by the exact flavor name so that a future
    ``CySOC_Malware_Respond_1_1`` still finds its own entry.
    """
    template_cfg = (reasoning or {}).get(template_name) or {}
    responses = template_cfg.get("response") or {}
    if not isinstance(responses, dict):
        return None
    for name, cfg in responses.items():
        if str(name).startswith(responder_base_name) and isinstance(cfg, dict):
            return cfg
    return None


def find_usm_template(reasoning_doc, mappings_doc, org, title, responder_base_name):
    """Resolve the ``usm_template`` for a case. Returns ``(template, template_name)``.

    ``template`` is None when the org/case type has no template configured — the caller then
    falls back to the responder's built-in ticket layout. ``template_name`` is returned even
    when there is no template, so the caller can say which case type it matched.
    """
    reasoning = select_org_config(reasoning_doc, org)
    mappings = select_org_config(mappings_doc, org)
    template_name = resolve_template_name(title, mappings)
    if not template_name:
        return None, None
    entry = find_response_entry(reasoning, template_name, responder_base_name)
    if not isinstance(entry, dict):
        return None, template_name
    usm_template = entry.get("usm_template")
    return (usm_template if isinstance(usm_template, dict) else None), template_name
