#!/usr/bin/env python3
# encoding: utf-8
"""Shared base class for the CySOC TheHive case responders (DCSync, Malware).

Provides what both responders have in common: the ``CySOC/Log`` task-logging
scaffolding (with run-level dedup), the TheHive / Defender / USM client
factories and shared config reads, MDE device isolation, and USM (service-desk)
ticketing on true-positive. Each subclass reads its own extra config, supplies a
log prefix via ``_log_prefix()``, declares its ``RESPONDER_BASE_NAME`` (used to find
its own entry in case-reasoning), optionally contributes template variables via
``_usm_extra_context()``, and implements the case evaluation in ``run()``.
"""
import time
from datetime import datetime, timezone

from cortexutils.responder import Responder

import case_reasoning
import templating
from defender_client import DefenderActionError, DefenderClient
from thehive_client import TheHiveClient, TheHiveError
from usm_client import TICKET_TYPE, USMClient, USMError

LOG_TASK_GROUP = "CySOC"
LOG_TASK_TITLE = "Log"


class CySOCResponder(Responder):
    # Prefix of this responder's Cortex flavor name, used to find its own entry under a case
    # template's ``response:`` map in case-reasoning.yml. Matched by prefix so a version bump
    # (CySOC_Malware_Respond_1_1) still resolves. Subclasses must set it to use USM templates.
    RESPONDER_BASE_NAME = None

    def __init__(self, job_directory=None):
        Responder.__init__(self, job_directory)
        self.thehive_url = self.get_param("config.TheHive URL", None, "TheHive URL is missing")
        self.thehive_api_key = self.get_param("config.TheHive API key", None, "TheHive API key is missing")
        # Azure credentials — required only when an MDE action is enabled (the subclass checks).
        self.tenant_id = self.get_param("config.Azure tenant ID", None)
        self.client_id = self.get_param("config.Azure app client ID", None)
        self.client_secret = self.get_param("config.Azure app client secret", None)
        # Device isolation (shared MDE containment), off by default.
        self.isolate_device_on_tp = self.get_param("config.Isolate device on true positive", False)
        self.full_isolation = self.get_param("config.Full isolation", False)
        # USM (service-desk) ticketing on true-positive, off by default. The public TheHive URL is the
        # browser-reachable base used to build the ticket's customerRef (the internal "TheHive URL" is a
        # cluster address not reachable from an analyst's browser). USM URL/key are required only when
        # ticket creation is enabled (checked by the subclass).
        self.thehive_public_url = self.get_param("config.TheHive public URL", None)
        self.create_usm_ticket_on_tp = self.get_param("config.Create USM ticket on true positive", False)
        self.usm_url = self.get_param("config.USM URL", None)
        self.usm_api_key = self.get_param("config.USM API key", None)
        self.update_usm_ticket_on_reeval = self.get_param("config.Update USM ticket on case reevaluation", False)
        # Per-org / per-case-type USM ticket templates. Both documents live in Consul KV (published
        # by sirp/thehive-config/thehive-configure.yml); they are read only when ticketing is on, so
        # an environment without USM gains no new dependency on Consul. Leaving either key unset
        # simply means every ticket uses the built-in layout.
        self.consul_url = self.get_param("config.Consul URL", "http://consul.service.consul:8500")
        self.consul_token = self.get_param("config.Consul ACL token", None)
        self.consul_kv_case_reasoning = self.get_param("config.Consul KV case reasoning", None)
        self.consul_kv_case_mappings = self.get_param("config.Consul KV case mappings", None)
        self._run_log_done = False

    # --- factories (kept separate so tests can substitute fakes) --------------
    def _thehive(self):
        return TheHiveClient(self.thehive_url, self.thehive_api_key)

    def _defender(self):
        return DefenderClient(self.tenant_id, self.client_id, self.client_secret)

    def _usm(self):
        return USMClient(self.usm_url, self.usm_api_key)

    # --- log prefix (the responder name analysts see in TheHive) --------------
    def _log_prefix(self):
        return self.__class__.__name__

    # --- task logging ---------------------------------------------------------
    def _log(self, thehive, case_id, message):
        """Best-effort: a logging hiccup must never fail the job whose result it's recording.

        Only the first call per run performs a dedup check against TheHive's last task log — this
        prevents repeating an identical run-level verdict from a previous execution. All subsequent
        calls within the same run bypass dedup so per-action entries are always written.
        """
        is_first = not self._run_log_done
        self._run_log_done = True
        try:
            thehive.log_to_task(case_id, LOG_TASK_GROUP, LOG_TASK_TITLE, message, dedup=is_first)
        except TheHiveError:
            pass

    def _log_failure(self, thehive, case_id, message):
        """Best-effort: only possible once a case/TheHive client is known, so it's a no-op before that."""
        if case_id and thehive:
            self._log(thehive, case_id, f"{self._log_prefix()}: FAILED — {message}")

    def _fail(self, thehive, case_id, message):
        self._log_failure(thehive, case_id, message)
        self.error(message)

    # --- shared MDE device containment ---------------------------------------
    def _isolate_devices(self, defender, devices, comment):
        """Isolate each device (Selective unless 'Full isolation'). ``devices`` is {device_id: host}.

        Returns a list of action-result dicts (one per device).
        """
        isolation_type = "Full" if self.full_isolation else "Selective"
        actions = []
        for device_id, host in devices.items():
            try:
                defender.isolate_device(device_id, comment, full=self.full_isolation)
                actions.append(
                    {
                        "type": "isolate_device",
                        "target": host,
                        "id": device_id,
                        "success": True,
                        "detail": None,
                        "isolation_type": isolation_type,
                    }
                )
            except DefenderActionError as exc:
                actions.append(
                    {
                        "type": "isolate_device",
                        "target": host,
                        "id": device_id,
                        "success": False,
                        "detail": str(exc),
                        "isolation_type": isolation_type,
                    }
                )
        return actions

    # --- USM (service-desk) ticketing ----------------------------------------
    @staticmethod
    def _usm_title(case):
        """USM ticket title, prefixed with the TheHive case number (e.g. 'Case #350 - <title>').

        Falls back to the bare title if the case number isn't present.
        """
        title = case.get("title", "")
        number = case.get("caseId") or case.get("number")
        return f"Case #{number} - {title}" if number else title

    @staticmethod
    def _usm_severity(severity):
        """Map a TheHive severity (1=Low..4=Critical) to the USM urgency/impact scale (1=critical..4=Low).

        The two scales are inverted. Falls back to "3" (medium) for a missing/unexpected value.
        """
        return {4: "1", 3: "2", 2: "3", 1: "4"}.get(severity, "3")

    @staticmethod
    def _format_actions(actions):
        """The containment-action lines, one per action, without a heading ("" when there are none).

        Also exposed to ticket templates as ``[[ actions ]]``, which is why the heading lives in
        the caller rather than here — a template supplies its own wording.
        """
        lines = []
        for a in actions or []:
            method = a.get("method")
            where = f" in {method}" if method else ""
            status = "OK" if a["success"] else "FAILED"
            detail = f" — {a['detail']}" if a.get("detail") else ""
            lines.append(f"- {a['type']}{where} on {a['target']} ({a['id']}): {status}{detail}")
        return "\n".join(lines)

    @staticmethod
    def _format_actions_summary(actions):
        """Short tally of the containment actions, e.g. "2 succeeded, 1 failed" ("" when none)."""
        if not actions:
            return ""
        ok = sum(1 for a in actions if a.get("success"))
        failed = len(actions) - ok
        parts = []
        if ok:
            parts.append(f"{ok} succeeded")
        if failed:
            parts.append(f"{failed} failed")
        return ", ".join(parts)

    @classmethod
    def _build_usm_desc(cls, case, actions):
        """Ticket description: the case description plus, if any, the containment actions taken.

        This is the built-in layout, used whenever the case's organisation and case type have no
        ``usm_template`` in case-reasoning.yml.
        """
        desc = case.get("description") or ""
        block = cls._format_actions(actions)
        if block:
            desc = f"{desc}\n\nContainment actions taken:\n{block}"
        return desc

    # --- USM ticket templating (per organisation, per case type) --------------
    def _usm_extra_context(self):
        """Responder-specific template variables. Overridden by the subclasses; empty by default."""
        return {}

    @staticmethod
    def _custom_fields(case):
        """Flatten TheHive custom fields to ``{name: value}`` for ``[[ cf.<name> ]]`` lookups.

        The v0 rendering a responder is handed is ``{name: {typeName: value, "order": n}}``; the
        v1 query rendering is a list of ``{name, value}``. Both are accepted.
        """
        cfs = (case or {}).get("customFields")
        flat = {}
        if isinstance(cfs, list):
            for cf in cfs:
                if isinstance(cf, dict) and cf.get("name"):
                    flat[cf["name"]] = cf.get("value")
        elif isinstance(cfs, dict):
            for name, entry in cfs.items():
                if isinstance(entry, dict):
                    values = [v for k, v in entry.items() if k != "order"]
                    flat[name] = values[0] if values else None
                else:
                    flat[name] = entry
        return flat

    def _usm_context(self, case, case_id, actions, customer_ref, org):
        """Variables available to a ticket template as ``[[ name ]]``.

        Subclass additions (via ``_usm_extra_context``) are merged last so a responder can expose
        its own verdict material without the base needing to know about it.
        """
        context = {
            "title": case.get("title"),
            "description": case.get("description"),
            "summary": case.get("summary"),
            "severity": case.get("severity"),
            "usm_severity": self._usm_severity(case.get("severity")),
            "caseId": case.get("caseId") or case.get("number"),
            "case_id": case_id,
            "case_url": customer_ref,
            "tags": ", ".join(case.get("tags") or []),
            "owner": case.get("owner"),
            "tlp": case.get("tlp"),
            "pap": case.get("pap"),
            "status": case.get("status"),
            "startDate": case.get("startDate"),
            "organisation": org,
            "internal_ref": case_reasoning.internal_ref_of(case),
            "verdict": "true-positive",
            "responder": self._log_prefix(),
            "now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actions": self._format_actions(actions),
            "actions_summary": self._format_actions_summary(actions),
            "cf": self._custom_fields(case),
        }
        context.update(self._usm_extra_context())
        return context

    def _resolve_usm_template(self, case, thehive, case_id, org):
        """Find this case's ``usm_template``. Returns ``(template, template_name)``, either may be None.

        Best-effort by design: a missing key, an unreachable Consul, or a malformed document all
        fall back to the built-in ticket layout with an explanatory line on the case, rather than
        failing the job. A responder that cannot reach its template must still raise the ticket —
        losing the ticket entirely is worse than sending one with the default wording.
        """
        if not (self.consul_kv_case_reasoning and self.consul_kv_case_mappings):
            return None, None
        try:
            reasoning_doc = case_reasoning.read_kv_yaml(
                self.consul_url, self.consul_kv_case_reasoning, self.consul_token
            )
            mappings_doc = case_reasoning.read_kv_yaml(
                self.consul_url, self.consul_kv_case_mappings, self.consul_token
            )
        except (case_reasoning.CaseReasoningError, OSError) as exc:
            self._log(
                thehive,
                case_id,
                f"{self._log_prefix()}: USM ticket template lookup failed, using the built-in "
                f"template — {exc}",
            )
            return None, None
        return case_reasoning.find_usm_template(
            reasoning_doc, mappings_doc, org, case.get("title") or "", self.RESPONDER_BASE_NAME or ""
        )

    def _usm_payload(self, case, case_id, actions, customer_ref, template, context, thehive):
        """Assemble the /api/create body: the built-in defaults, then the template on top.

        Starting from the defaults means a template that sets only ``desc`` keeps the standard
        title and severity mapping, and an absent template reproduces the pre-template ticket
        exactly. A template key set to null drops that field from the body — except
        ``customerRef``, which is not templatable at all (see below).
        """
        payload = {
            "title": self._usm_title(case),
            "desc": self._build_usm_desc(case, actions),
            "urgencyMap1": self._usm_severity(case.get("severity")),
            "impactMap1": self._usm_severity(case.get("severity")),
            "type": TICKET_TYPE,
            "customerRef": customer_ref,
        }
        if not template:
            return payload
        rendered, unknown = templating.render_payload(template, context)
        if unknown:
            self._log(
                thehive,
                case_id,
                f"{self._log_prefix()}: USM ticket template referenced unknown variable(s), rendered "
                f"as empty: {', '.join(unknown)}",
            )
        # customerRef is the create-idempotency key and what find_ticket_no() looks the ticket up by,
        # so it is owned by the responder: a template that sets (or nulls) it is ignored rather than
        # honoured, since either would break the link back to the case.
        if rendered.pop("customerRef", customer_ref) != customer_ref:
            self._log(
                thehive,
                case_id,
                f"{self._log_prefix()}: USM ticket template sets customerRef — ignored, the case "
                f"URL is always used ({customer_ref})",
            )
        payload.update(rendered)
        return payload

    def _lookup_ticket_no(self, usm, customer_ref, thehive, case_id):
        """Best-effort resolve of the ticket number for a customerRef.

        The number is reporting metadata, not a gate: a lookup failure must never fail the job
        (for the create path, the ticket already exists; the only fatal USM gate is creation
        itself). Returns the ticket number or None. The reason it could not be resolved (an error,
        or simply no match) is logged to the CySOC/Log task so a null ``ticket_no`` is diagnosable
        rather than silent.
        """
        prefix = self._log_prefix()
        try:
            ticket_no = usm.find_ticket_no(customer_ref)
        except USMError as exc:
            self._log(thehive, case_id, f"{prefix}: USM ticket number lookup failed — {exc}")
            return None
        if not ticket_no:
            self._log(
                thehive, case_id, f"{prefix}: USM ticket number not found for customerRef {customer_ref}"
            )
        return ticket_no

    def _tag_usm_ticket(self, thehive, case, case_id, ticket_no):
        if ticket_no:
            thehive.add_case_tags(
                case_id,
                [f"ext:Ticket={ticket_no};{time.time_ns() // 1_000_000}"],
                case.get("tags") or [],
            )

    def _handle_usm(self, thehive, case, case_id, actions):
        """Create (or, on reevaluation, update) a USM ticket for a true-positive case.

        No-op unless 'Create USM ticket on true positive' is enabled (returns None). Otherwise
        returns a dict ``{"status", "ticketno", "template"}`` recording the outcome for the JSON
        report — ``status`` is "created" or "exists", ``ticket_no`` is the resolved USM ticket
        number (best-effort; None if it could not be looked up), and ``template`` names the case
        type whose ``usm_template`` was applied (None for the built-in layout).

        The ticket body comes from the case's organisation/case-type ``usm_template`` in
        case-reasoning.yml when one is configured, and from the built-in layout otherwise; see
        ``_resolve_usm_template``. Template resolution never fails the job.

        Creation failure fails the job (the only USM failure that does); a customerRef that already
        exists is benign and, when 'Update USM ticket on case reevaluation' is enabled, the existing
        ticket is updated best-effort (an update failure is logged, not fatal).
        """
        if not self.create_usm_ticket_on_tp:
            return None
        usm = self._usm()
        prefix = self._log_prefix()
        customer_ref = f"{self.thehive_public_url.rstrip('/')}/index.html#!/case/{case_id}/details"
        org = case_reasoning.org_of(case, self.get_param("parameters.organisation", None))
        template, template_name = self._resolve_usm_template(case, thehive, case_id, org)
        context = self._usm_context(case, case_id, actions, customer_ref, org)
        payload = self._usm_payload(case, case_id, actions, customer_ref, template, context, thehive)
        origin = (
            f"template '{template_name}'" + (f" of organisation '{org}'" if org else "")
            if template
            else "the built-in template"
        )
        desc = payload.get("desc", "")
        try:
            result, ticket_no = usm.create_ticket(payload)
        except USMError as exc:
            self._fail(thehive, case_id, f"USM ticket creation failed: {exc}")
            return None  # unreachable — _fail exits — but keeps the contract explicit
        if result == "created":
            # The create response usually echoes the new ticket number; only fall back to a
            # readall lookup if it didn't (e.g. an older API shape).
            if not ticket_no:
                ticket_no = self._lookup_ticket_no(usm, customer_ref, thehive, case_id)
            self._tag_usm_ticket(thehive, case, case_id, ticket_no)
            suffix = f" (ticket {ticket_no})" if ticket_no else ""
            self._log(
                thehive, case_id, f"{prefix}: USM ticket created from {origin} — {customer_ref}{suffix}"
            )
            return {"status": "created", "ticketno": ticket_no, "template": template_name if template else None}
        # result == "exists": the case already has a ticket — resolve its number by lookup
        ticket_no = self._lookup_ticket_no(usm, customer_ref, thehive, case_id)
        self._tag_usm_ticket(thehive, case, case_id, ticket_no)
        if self.update_usm_ticket_on_reeval:
            try:
                if ticket_no:
                    usm.update_ticket(ticket_no, desc)
                    self._log(thehive, case_id, f"{prefix}: USM ticket {ticket_no} updated")
                else:
                    self._log(
                        thehive,
                        case_id,
                        f"{prefix}: USM ticket exists but its number could not be resolved — update skipped",
                    )
            except USMError as exc:
                self._log(thehive, case_id, f"{prefix}: FAILED to update existing USM ticket — {exc}")
        else:
            self._log(thehive, case_id, f"{prefix}: USM ticket already exists — update disabled, skipped")
        return {"status": "exists", "ticketno": ticket_no, "template": template_name if template else None}
