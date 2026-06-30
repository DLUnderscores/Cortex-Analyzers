#!/usr/bin/env python3
# encoding: utf-8
"""Shared base class for the CySOC TheHive case responders (DCSync, Malware).

Provides what both responders have in common: the ``CySOC/Log`` task-logging
scaffolding (with run-level dedup), the TheHive / Defender / USM client
factories and shared config reads, MDE device isolation, and USM (service-desk)
ticketing on true-positive. Each subclass reads its own extra config, supplies a
log prefix via ``_log_prefix()``, and implements the case evaluation in ``run()``.
"""
from cortexutils.responder import Responder

from defender_client import DefenderActionError, DefenderClient
from thehive_client import TheHiveClient, TheHiveError
from usm_client import USMClient, USMError

LOG_TASK_GROUP = "CySOC"
LOG_TASK_TITLE = "Log"


class CySOCResponder(Responder):
    def __init__(self, job_directory=None):
        Responder.__init__(self, job_directory)
        self.thehive_url = self.get_param("config.TheHive URL", None, "TheHive URL is missing")
        self.thehive_api_key = self.get_param("config.TheHive API key", None, "TheHive API key is missing")
        self.close_on_fp = self.get_param("config.Close on false positive", True)
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
    def _build_usm_desc(case, actions):
        """Ticket description: the case description plus, if any, the containment actions taken."""
        desc = case.get("description") or ""
        if actions:
            lines = []
            for a in actions:
                method = a.get("method")
                where = f" in {method}" if method else ""
                status = "OK" if a["success"] else "FAILED"
                detail = f" — {a['detail']}" if a.get("detail") else ""
                lines.append(f"- {a['type']}{where} on {a['target']} ({a['id']}): {status}{detail}")
            desc = f"{desc}\n\nContainment actions taken:\n" + "\n".join(lines)
        return desc

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

    def _handle_usm(self, thehive, case, case_id, actions):
        """Create (or, on reevaluation, update) a USM ticket for a true-positive case.

        No-op unless 'Create USM ticket on true positive' is enabled (returns None). Otherwise
        returns a dict ``{"status", "ticketno"}`` recording the outcome for the JSON report —
        ``status`` is "created" or "exists" and ``ticket_no`` is the resolved USM ticket number
        (best-effort; None if it could not be looked up).

        Creation failure fails the job (the only USM failure that does); a customerRef that already
        exists is benign and, when 'Update USM ticket on case reevaluation' is enabled, the existing
        ticket is updated best-effort (an update failure is logged, not fatal).
        """
        if not self.create_usm_ticket_on_tp:
            return None
        usm = self._usm()
        prefix = self._log_prefix()
        customer_ref = f"{self.thehive_public_url.rstrip('/')}/index.html#!/case/{case_id}/details"
        title = self._usm_title(case)
        desc = self._build_usm_desc(case, actions)
        severity = self._usm_severity(case.get("severity"))
        try:
            result, ticket_no = usm.create_ticket(title, desc, severity, customer_ref)
        except USMError as exc:
            self._fail(thehive, case_id, f"USM ticket creation failed: {exc}")
            return None  # unreachable — _fail exits — but keeps the contract explicit
        if result == "created":
            # The create response usually echoes the new ticket number; only fall back to a
            # readall lookup if it didn't (e.g. an older API shape).
            if not ticket_no:
                ticket_no = self._lookup_ticket_no(usm, customer_ref, thehive, case_id)
            suffix = f" (ticket {ticket_no})" if ticket_no else ""
            self._log(thehive, case_id, f"{prefix}: USM ticket created — {customer_ref}{suffix}")
            return {"status": "created", "ticketno": ticket_no}
        # result == "exists": the case already has a ticket — resolve its number by lookup
        ticket_no = self._lookup_ticket_no(usm, customer_ref, thehive, case_id)
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
        return {"status": "exists", "ticketno": ticket_no}
