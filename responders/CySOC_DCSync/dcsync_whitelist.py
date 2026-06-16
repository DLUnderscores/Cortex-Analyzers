#!/usr/bin/env python3
# encoding: utf-8
"""DCSync whitelist responders (TheHive case level).

check:  Evaluate every (user, host) pair derived from the case observables
        against the Consul KV whitelist. All pairs whitelisted → closes the
        case as a false positive (optional); any pair unknown → closes the
        case as a true positive. Canonical ids come exclusively from the
        MicrosoftDefender enrichment reports attached to the observables; an
        observable without enrichment fails the job (fail-safe: the case is
        never closed on incomplete information). If the whitelist itself
        isn't configured, the case is left open instead of being closed as a
        true positive, since "couldn't check" isn't the same as "checked and
        it's bad".

update: Write every (user, host) pair of the case to the whitelist. Run by
        the analyst after a true positive is rejected at check level 2.

Both services append a one-line summary of the decision to a TheHive task
(group "CySOC", title "Log"), creating it on the case if it doesn't exist
yet, so analysts can see why a case was auto-closed without digging through
the responder job output.
"""
import traceback
from datetime import datetime, timezone

from cortexutils.responder import Responder

from thehive_client import TheHiveClient, TheHiveError
from whitelist import ConsulKVError, ConsulWhitelist, PairResolver

LOG_TASK_GROUP = "CySOC"
LOG_TASK_TITLE = "Log"


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

    # Factories kept separate so tests can substitute fakes.
    def _thehive(self):
        return TheHiveClient(self.thehive_url, self.thehive_api_key)

    def _whitelist(self):
        return ConsulWhitelist(self.consul_url, self.consul_kv_whitelist, token=self.consul_token)

    def _resolver(self):
        return PairResolver()

    def _log(self, thehive, case_id, message):
        """Best-effort: a logging hiccup must never fail the job whose result it's recording."""
        try:
            thehive.log_to_task(case_id, LOG_TASK_GROUP, LOG_TASK_TITLE, message)
        except TheHiveError:
            pass

    def run(self):
        try:
            case = self.get_data()
            if not isinstance(case, dict):
                self.error(f"Expected a case object, got: {type(case).__name__}")
            case_id = case.get("_id") or case.get("id")
            if not case_id:
                self.error("Case id is missing from responder input")

            thehive = self._thehive()
            observables = thehive.get_case_observables(case_id)
            pairs, unresolved, pair_selection = self._resolver().resolve(observables)

            if unresolved:
                details = "; ".join(f"{u['dataType']} '{u['data']}' ({u['reason']})" for u in unresolved)
                self.error(f"Cannot evaluate case {case_id} — unresolved observables: {details}")
            if not pairs:
                self.error(
                    f"Cannot evaluate case {case_id} — no user+host pair could be derived from the case observables"
                )

            if self.service == "check":
                whitelist = self._whitelist() if self.consul_kv_whitelist else None
                self.check(case, case_id, thehive, whitelist, pairs, pair_selection)
            elif self.service == "update":
                if not self.consul_kv_whitelist:
                    self.error("Consul KV whitelist key is missing")
                self.update(case, case_id, thehive, self._whitelist(), pairs, pair_selection)
            else:
                self.error(f"Unknown service: {self.service}")
        except (TheHiveError, ConsulKVError) as exc:
            self.error(str(exc))
        except SystemExit:
            raise
        except Exception:
            self.unexpectedError(traceback.format_exc())

    def check(self, case, case_id, thehive, whitelist, pairs, pair_selection):
        entries = whitelist.entries() if whitelist else {}
        matched, unmatched = [], []
        for pair in pairs:
            if pair["key"] in entries:
                matched.append({**pair, "entry": entries[pair["key"]]})
            else:
                unmatched.append(pair)

        case_closed = False
        if whitelist is None:
            verdict = "true-positive"
            log_message = (
                "DCSync check: whitelist not configured — cannot confirm status, case left open for "
                "manual review. Pair(s) evaluated: " + ", ".join(f"{p['user']}@{p['host']}" for p in pairs)
            )
        elif unmatched:
            verdict = "true-positive"
            log_message = (
                "DCSync check: closed automatically as a true-positive — user+host pair(s) not found in "
                "the whitelist: " + ", ".join(f"{p['user']}@{p['host']}" for p in unmatched)
            )
            thehive.close_case_true_positive(case_id)
            case_closed = True
        else:
            verdict = "false-positive"
            whitelisted = ", ".join(f"{p['user']}@{p['host']}" for p in matched)
            if self.close_on_fp:
                log_message = f"DCSync check: closed automatically as a false-positive — whitelisted user+host pair(s): {whitelisted}"
                thehive.close_case_false_positive(case_id)
                case_closed = True
            else:
                log_message = f"DCSync check: verdict false-positive (not auto-closed — close_on_fp disabled) — whitelisted user+host pair(s): {whitelisted}"

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

        case_number = case.get("caseId") or case.get("number")
        parts = []
        if added:
            parts.append("added to whitelist: " + ", ".join(f"{p['user']}@{p['host']}" for p in added))
        if refreshed:
            parts.append(
                "already on whitelist (metadata refreshed): " + ", ".join(f"{p['user']}@{p['host']}" for p in refreshed)
            )
        self._log(thehive, case_id, f"DCSync update (case #{case_number}): " + "; ".join(parts))

        self.report(
            {
                "service": "update",
                "case_id": case_id,
                "pair_selection": pair_selection,
                "added": added,
                "already_present": refreshed,
            }
        )


if __name__ == "__main__":
    DCSyncWhitelistResponder().run()
