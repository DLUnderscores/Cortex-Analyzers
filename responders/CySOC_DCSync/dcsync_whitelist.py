#!/usr/bin/env python3
# encoding: utf-8
"""DCSync whitelist responders (TheHive case level).

check:  Evaluate every (user, host) pair derived from the case observables
        against the Consul KV whitelist. All pairs whitelisted → closes the
        case as a false positive (optional); any pair unknown → optionally
        disables the user's Entra account and/or isolates the source device
        (only the non-whitelisted users/devices — see below), then closes
        the case as a true positive only if every attempted action
        succeeded. Canonical ids come exclusively from the MicrosoftDefender
        enrichment reports attached to the observables; an observable
        without enrichment fails the job (fail-safe: the case is never
        closed on incomplete information). If the whitelist itself isn't
        configured, the case is left open instead of being closed as a true
        positive, since "couldn't check" isn't the same as "checked and
        it's bad".

        Containment actions (disable_user_on_tp / isolate_device_on_tp) are
        derived only from the non-whitelisted ("unmatched") pairs, so a
        whitelisted user/device sharing a case with a non-whitelisted one is
        never touched. Both are off by default; neither is attempted when
        the verdict is false-positive (there are no unmatched pairs then) or
        when the whitelist isn't configured (fail-safe — see above).

update: Write every (user, host) pair of the case to the whitelist and close
        the case as a false positive. Run by the analyst after a true
        positive is rejected at check level 2.

Both services append a one-line summary of the decision to a TheHive task
(group "CySOC", title "Log"), creating it on the case if it doesn't exist
yet, so analysts can see why a case was auto-closed (or why it wasn't, e.g.
a containment action failed) without digging through the responder job
output.
"""
import traceback
from datetime import datetime, timezone

from cortexutils.responder import Responder

from defender_client import DefenderActionError, DefenderClient
from thehive_client import TheHiveClient, TheHiveError
from whitelist import ConsulKVError, ConsulWhitelist, PairResolver

LOG_TASK_GROUP = "CySOC"
LOG_TASK_TITLE = "Log"

# Log-line prefixes, named after the responder definitions analysts see in TheHive.
LOG_PREFIX = {"check": "CySOC_DCSync_Respond", "update": "CySOC_DCSync_UpdateWhitelist"}


class DCSyncWhitelistResponder(Responder):
    def __init__(self, job_directory=None):
        Responder.__init__(self, job_directory)
        self.service = self.get_param("config.service", None, "Service parameter is missing")
        self.thehive_url = self.get_param("config.thehive_url", None, "TheHive URL is missing")
        self.thehive_api_key = self.get_param("config.thehive_api_key", None, "TheHive API key is missing")
        self.consul_url = self.get_param("config.consul_url", "http://consul.service.consul:8500")
        # Optional for "check" — an unconfigured whitelist fails safe to "not whitelisted"
        # rather than blocking the job. Required for "update" (enforced in run()).
        self.consul_kv_whitelist = self.get_param("config.consul_kv_whitelist", None)
        self.consul_token = self.get_param("config.consul_token", None)
        self.close_on_fp = self.get_param("config.close_on_fp", True)
        # Containment actions on true-positive, off by default. tenant_id/client_id/
        # client_secret are only required when one of these is enabled (checked in run()).
        self.tenant_id = self.get_param("config.tenant_id", None)
        self.client_id = self.get_param("config.client_id", None)
        self.client_secret = self.get_param("config.client_secret", None)
        self.disable_user_on_tp = self.get_param("config.disable_user_on_tp", False)
        self.isolate_device_on_tp = self.get_param("config.isolate_device_on_tp", False)
        self.full_isolation = self.get_param("config.full_isolation", False)

    # Factories kept separate so tests can substitute fakes.
    def _thehive(self):
        return TheHiveClient(self.thehive_url, self.thehive_api_key)

    def _whitelist(self):
        return ConsulWhitelist(self.consul_url, self.consul_kv_whitelist, token=self.consul_token)

    def _defender(self):
        return DefenderClient(self.tenant_id, self.client_id, self.client_secret)

    def _resolver(self):
        return PairResolver()

    def _log(self, thehive, case_id, message):
        """Best-effort: a logging hiccup must never fail the job whose result it's recording."""
        try:
            thehive.log_to_task(case_id, LOG_TASK_GROUP, LOG_TASK_TITLE, message)
        except TheHiveError:
            pass

    def _log_failure(self, thehive, case_id, message):
        """Best-effort: only possible once a case/TheHive client is known, so it's a no-op before that."""
        if case_id and thehive:
            prefix = LOG_PREFIX.get(self.service, self.service)
            self._log(thehive, case_id, f"{prefix}: FAILED — {message}")

    def _fail(self, thehive, case_id, message):
        self._log_failure(thehive, case_id, message)
        self.error(message)

    def run(self):
        case_id = None
        thehive = None
        try:
            case = self.get_data()
            if not isinstance(case, dict):
                self._fail(thehive, case_id, f"Expected a case object, got: {type(case).__name__}")
            case_id = case.get("_id") or case.get("id")
            if not case_id:
                self._fail(thehive, case_id, "Case id is missing from responder input")

            thehive = self._thehive()
            observables = thehive.get_case_observables(case_id)
            pairs, unresolved, pair_selection = self._resolver().resolve(observables)

            if unresolved:
                details = "; ".join(f"{u['dataType']} '{u['data']}' ({u['reason']})" for u in unresolved)
                self._fail(thehive, case_id, f"Cannot evaluate case {case_id} — unresolved observables: {details}")
            if not pairs:
                self._fail(
                    thehive,
                    case_id,
                    f"Cannot evaluate case {case_id} — no user+host pair could be derived from the case observables",
                )

            if self.service == "check":
                actions_enabled = self.disable_user_on_tp or self.isolate_device_on_tp
                if actions_enabled and not (self.tenant_id and self.client_id and self.client_secret):
                    self._fail(
                        thehive,
                        case_id,
                        "tenant_id/client_id/client_secret are required when disable_user_on_tp or "
                        "isolate_device_on_tp is enabled",
                    )
                whitelist = self._whitelist() if self.consul_kv_whitelist else None
                defender = self._defender() if actions_enabled else None
                self.check(case, case_id, thehive, whitelist, defender, pairs, pair_selection)
            elif self.service == "update":
                if not self.consul_kv_whitelist:
                    self._fail(thehive, case_id, "Consul KV whitelist key is missing")
                self.update(case, case_id, thehive, self._whitelist(), pairs, pair_selection)
            else:
                self._fail(thehive, case_id, f"Unknown service: {self.service}")
        except (TheHiveError, ConsulKVError, DefenderActionError) as exc:
            self._fail(thehive, case_id, str(exc))
        except SystemExit:
            raise
        except Exception as exc:
            self._log_failure(thehive, case_id, f"unexpected error: {exc}")
            self.error(traceback.format_exc())

    def _containment_actions(self, defender, case, unmatched):
        """Run the configured containment actions on the unmatched (non-whitelisted) pairs only.

        Returns (actions, all_succeeded); all_succeeded is vacuously True when neither
        disable_user_on_tp nor isolate_device_on_tp is enabled.
        """
        actions = []

        if self.disable_user_on_tp:
            users = {}
            for pair in unmatched:
                users.setdefault(
                    pair["user_id"], {"display": pair["user"], "predicate": pair["user_id_predicate"]}
                )
            for user_id, info in users.items():
                if info["predicate"] != "Account_Object_ID":
                    actions.append(
                        {
                            "type": "disable_user",
                            "target": info["display"],
                            "id": user_id,
                            "success": False,
                            "detail": "no Entra account id available (only on-prem AD id resolved)",
                        }
                    )
                    continue
                try:
                    defender.disable_user(user_id)
                    actions.append(
                        {"type": "disable_user", "target": info["display"], "id": user_id, "success": True, "detail": None}
                    )
                except DefenderActionError as exc:
                    actions.append(
                        {
                            "type": "disable_user",
                            "target": info["display"],
                            "id": user_id,
                            "success": False,
                            "detail": str(exc),
                        }
                    )

        if self.isolate_device_on_tp:
            devices = {}
            for pair in unmatched:
                devices.setdefault(pair["device_id"], pair["host"])
            comment = f"CySOC DCSync — TheHive case {case.get('caseId') or case.get('number')}"
            for device_id, host in devices.items():
                try:
                    defender.isolate_device(device_id, comment, full=self.full_isolation)
                    actions.append(
                        {"type": "isolate_device", "target": host, "id": device_id, "success": True, "detail": None}
                    )
                except DefenderActionError as exc:
                    actions.append(
                        {
                            "type": "isolate_device",
                            "target": host,
                            "id": device_id,
                            "success": False,
                            "detail": str(exc),
                        }
                    )

        return actions, all(a["success"] for a in actions)

    def check(self, case, case_id, thehive, whitelist, defender, pairs, pair_selection):
        entries = whitelist.entries() if whitelist else {}
        matched, unmatched = [], []
        for pair in pairs:
            if pair["key"] in entries:
                matched.append({**pair, "entry": entries[pair["key"]]})
            else:
                unmatched.append(pair)

        case_closed = False
        actions = []
        if whitelist is None:
            verdict = "true-positive"
            log_message = (
                f"{LOG_PREFIX['check']}: whitelist not configured — cannot confirm status, case left open "
                "for manual review. Pair(s) evaluated: " + ", ".join(f"{p['user']}@{p['host']}" for p in pairs)
            )
        elif unmatched:
            verdict = "true-positive"
            base_message = "user+host pair(s) not found in the whitelist: " + ", ".join(
                f"{p['user']}@{p['host']}" for p in unmatched
            )
            actions, all_succeeded = self._containment_actions(defender, case, unmatched)
            action_summary = "; ".join(
                f"{a['type']}: {a['target']} ({'success' if a['success'] else 'FAILED — ' + a['detail']})"
                for a in actions
            )
            if all_succeeded:
                thehive.close_case_true_positive(case_id)
                case_closed = True
                log_message = f"{LOG_PREFIX['check']}: closed automatically as a true-positive — {base_message}"
            else:
                log_message = (
                    f"{LOG_PREFIX['check']}: true-positive, NOT closed — one or more containment actions "
                    f"failed — {base_message}"
                )
            if action_summary:
                log_message += "; " + action_summary
        else:
            verdict = "false-positive"
            whitelisted = ", ".join(f"{p['user']}@{p['host']}" for p in matched)
            if self.close_on_fp:
                log_message = f"{LOG_PREFIX['check']}: closed automatically as a false-positive — whitelisted user+host pair(s): {whitelisted}"
                thehive.close_case_false_positive(case_id)
                case_closed = True
            else:
                log_message = f"{LOG_PREFIX['check']}: verdict false-positive (not auto-closed — close_on_fp disabled) — whitelisted user+host pair(s): {whitelisted}"

        self._log(thehive, case_id, log_message)

        self.report(
            {
                "service": "check",
                "case_id": case_id,
                "verdict": verdict,
                "whitelist_configured": whitelist is not None,
                "pair_selection": pair_selection,
                "pairs_evaluated": len(pairs),
                "matched": matched,
                "unmatched": unmatched,
                "actions": actions,
                "case_closed": case_closed,
            }
        )

    def update(self, case, case_id, thehive, whitelist, pairs, pair_selection):
        entries = whitelist.entries()
        added, refreshed = [], []
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for pair in pairs:
            metadata = {
                "account": pair["user"],
                "account_object_id": pair["user_id"],
                "hostname": pair["host"],
                "device_id": pair["device_id"],
                "added_by": case.get("owner", ""),
                "added_at": now,
                "case_id": case_id,
                "case_number": case.get("caseId") or case.get("number"),
                "reason": case.get("title", ""),
            }
            whitelist.put(pair["key"], metadata)
            (refreshed if pair["key"] in entries else added).append({**pair, "entry": metadata})

        thehive.close_case_false_positive(case_id)

        parts = []
        if added:
            parts.append("added to whitelist: " + ", ".join(f"{p['user']}@{p['host']}" for p in added))
        if refreshed:
            parts.append(
                "already on whitelist (metadata refreshed): " + ", ".join(f"{p['user']}@{p['host']}" for p in refreshed)
            )
        parts.append("case closed as false-positive")
        self._log(thehive, case_id, f"{LOG_PREFIX['update']}: " + "; ".join(parts))

        self.report(
            {
                "service": "update",
                "case_id": case_id,
                "pair_selection": pair_selection,
                "added": added,
                "already_present": refreshed,
                "case_closed": True,
            }
        )


if __name__ == "__main__":
    DCSyncWhitelistResponder().run()
