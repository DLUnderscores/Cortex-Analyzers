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
output. The shared scaffolding (task logging, client factories, MDE device
isolation, USM ticketing) lives in base.CySOCResponder.
"""
import traceback
from datetime import datetime, timezone

from base import CySOCResponder
from defender_client import DefenderActionError
from thehive_client import TheHiveError
from whitelist import ConsulKVError, ConsulWhitelist, PairResolver

# Log-line prefixes, named after the responder definitions analysts see in TheHive.
LOG_PREFIX = {"check": "CySOC_DCSync_Respond", "update": "CySOC_DCSync_UpdateWhitelist"}


class DCSyncWhitelistResponder(CySOCResponder):
    def __init__(self, job_directory=None):
        super().__init__(job_directory)
        self.service = self.get_param("config.service", None, "Service parameter is missing")
        self.consul_url = self.get_param("config.Consul URL", "http://consul.service.consul:8500")
        # Optional for "check" — an unconfigured whitelist fails safe to "not whitelisted"
        # rather than blocking the job. Required for "update" (enforced in run()).
        self.consul_kv_whitelist = self.get_param("config.Consul KV whitelist", None)
        self.consul_token = self.get_param("config.Consul ACL token", None)
        # User-identity containment actions on true-positive, off by default. Azure credentials are
        # only required when one of these (or device isolation) is enabled (checked in run()).
        self.disable_user_on_tp = self.get_param("config.Disable user on true positive", False)
        self.force_password_reset_on_tp = self.get_param("config.Force password reset on true positive", False)
        self.revoke_sessions_on_tp = self.get_param("config.Revoke sessions on true positive", False)

    def _log_prefix(self):
        return LOG_PREFIX.get(self.service, self.service)

    def _whitelist(self):
        return ConsulWhitelist(self.consul_url, self.consul_kv_whitelist, token=self.consul_token)

    def _resolver(self):
        return PairResolver()

    def run(self):
        self._run_log_done = False  # reset each run; first _log call gets dedup, rest bypass it
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
                    f"Cannot evaluate case {case_id} — need at least one MDE-resolved device and one "
                    "MDE-resolved user; every device/user observable was Not_Found in MDE, un-enriched, "
                    "or excluded as a destination",
                )

            if self.service == "check":
                actions_enabled = (
                    self.disable_user_on_tp
                    or self.force_password_reset_on_tp
                    or self.revoke_sessions_on_tp
                    or self.isolate_device_on_tp
                )
                if actions_enabled and not (self.tenant_id and self.client_id and self.client_secret):
                    self._fail(
                        thehive,
                        case_id,
                        "Azure tenant ID / Azure app client ID / Azure app client secret are required "
                        "when any true-positive containment action is enabled",
                    )
                if self.create_usm_ticket_on_tp and not (
                    self.usm_url and self.usm_api_key and self.thehive_public_url
                ):
                    self._fail(
                        thehive,
                        case_id,
                        "USM URL / USM API key / TheHive public URL are required when "
                        "'Create USM ticket on true positive' is enabled",
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

    @staticmethod
    def _unique_users(unmatched):
        """Deduplicate users from unmatched pairs, preserving first-occurrence order.

        Each entry carries the canonical id predicate plus the individual ids (any may be None),
        so containment can pick the right action per identity type.
        """
        seen = {}
        for pair in unmatched:
            seen.setdefault(
                pair["user_id"],
                {
                    "display": pair["user"],
                    "predicate": pair["user_id_predicate"],
                    "entra_object_id": pair.get("entra_object_id"),
                    "onprem_object_id": pair.get("onprem_object_id"),
                    "identity_account_id": pair.get("identity_account_id"),
                },
            )
        return seen

    @staticmethod
    def _try_graph_action(action_type, users, fn):
        """Run fn(user_id) for each unique user; checks Account_Object_ID predicate first."""
        results = []
        for user_id, info in users.items():
            if info["predicate"] != "Account_Object_ID":
                results.append(
                    {
                        "type": action_type,
                        "target": info["display"],
                        "id": user_id,
                        "success": False,
                        "detail": "no Entra account id available (only on-prem AD id resolved)",
                    }
                )
                continue
            try:
                fn(user_id)
                results.append(
                    {"type": action_type, "target": info["display"], "id": user_id, "success": True, "detail": None}
                )
            except DefenderActionError as exc:
                results.append(
                    {
                        "type": action_type,
                        "target": info["display"],
                        "id": user_id,
                        "success": False,
                        "detail": str(exc),
                    }
                )
        return results

    @staticmethod
    def _run_identity_action(users, action_type, ad_fn, entra_fn):
        """Run an identity action per unique user, choosing the path that works for the identity type.

        On-prem/hybrid accounts (identity-account id + on-prem AD id available) go through the Defender
        identityAccounts invokeAction endpoint via ad_fn(identity_account_id, account_id) — the only path
        that reaches an on-prem-mastered account; cloud-only Entra accounts fall back to the Graph call
        via entra_fn(entra_object_id). A user with neither usable id pair can't be actioned and is
        recorded as a failure. Used for disable and force_password_reset (both support activeDirectory).
        """
        results = []
        for info in users.values():
            target = info["display"]
            identity_account_id = info.get("identity_account_id")
            onprem_object_id = info.get("onprem_object_id")
            entra_object_id = info.get("entra_object_id")
            if identity_account_id and onprem_object_id:
                method, action_id = "AD", onprem_object_id
            elif entra_object_id:
                method, action_id = "Entra", entra_object_id
            else:
                results.append(
                    {
                        "type": action_type,
                        "target": target,
                        "id": onprem_object_id or entra_object_id or "",
                        "success": False,
                        "method": None,
                        "detail": "no AD identity-account id or Entra id available — "
                        "run the MicrosoftDefender user analyzer first",
                    }
                )
                continue
            try:
                if method == "AD":
                    ad_fn(identity_account_id, onprem_object_id)
                else:
                    entra_fn(entra_object_id)
                results.append(
                    {"type": action_type, "target": target, "id": action_id, "success": True,
                     "method": method, "detail": None}
                )
            except DefenderActionError as exc:
                results.append(
                    {"type": action_type, "target": target, "id": action_id, "success": False,
                     "method": method, "detail": str(exc)}
                )
        return results

    def _containment_actions(self, defender, case, unmatched):
        """Run the configured containment actions on the unmatched (non-whitelisted) pairs only.

        Actions execute in order: disable_user → force_password_reset → revoke_sessions → isolate_device.
        Returns (actions, all_succeeded); all_succeeded is vacuously True when no action is enabled.
        """
        actions = []

        any_user_action = self.disable_user_on_tp or self.force_password_reset_on_tp or self.revoke_sessions_on_tp
        if any_user_action:
            users = self._unique_users(unmatched)
            if self.disable_user_on_tp:
                actions.extend(
                    self._run_identity_action(users, "disable_user", defender.disable_user_ad, defender.disable_user_entra)
                )
            if self.force_password_reset_on_tp:
                actions.extend(
                    self._run_identity_action(
                        users, "force_password_reset", defender.force_password_reset_ad, defender.force_password_reset_entra
                    )
                )
            # Session revocation has no activeDirectory/entraID identityAccounts action (revokeAllSessions
            # is okta-only); it stays on the Graph revokeSignInSessions call, which targets the Entra object.
            if self.revoke_sessions_on_tp:
                actions.extend(self._try_graph_action("revoke_sessions", users, defender.revoke_sessions))

        if self.isolate_device_on_tp:
            devices = {}
            for pair in unmatched:
                devices.setdefault(pair["device_id"], pair["host"])
            comment = f"CySOC DCSync — TheHive case {case.get('caseId') or case.get('number')}"
            actions.extend(self._isolate_devices(defender, devices, comment))

        return actions, all(a["success"] for a in actions)

    def _log_action(self, thehive, case_id, action):
        """Log a single containment action result as its own task log entry."""
        prefix = LOG_PREFIX["check"]
        t, tgt, uid, ok, detail = (
            action["type"], action["target"], action["id"], action["success"], action.get("detail")
        )
        # method is "Entra" (cloud-only Graph call), "AD" (on-prem/hybrid invokeAction), or None when
        # no usable id was available to attempt the action at all. revoke_sessions is always Entra.
        method = action.get("method")
        where = f" in {method}" if method else ""
        if t == "disable_user":
            msg = (
                f"{prefix}: account disabled{where} — {tgt} ({uid})"
                if ok else
                f"{prefix}: FAILED to disable account{where} — {tgt} ({uid}): {detail}"
            )
        elif t == "force_password_reset":
            msg = (
                f"{prefix}: password reset forced{where} — {tgt} ({uid})"
                if ok else
                f"{prefix}: FAILED to force password reset{where} — {tgt} ({uid}): {detail}"
            )
        elif t == "revoke_sessions":
            msg = (
                f"{prefix}: sign-in sessions revoked in Entra — {tgt} ({uid})"
                if ok else
                f"{prefix}: FAILED to revoke sign-in sessions in Entra — {tgt} ({uid}): {detail}"
            )
        else:
            isolation_type = action.get("isolation_type", "Selective")
            msg = (
                f"{prefix}: device isolated ({isolation_type}) in MDE — {tgt} ({uid})"
                if ok else
                f"{prefix}: FAILED to isolate device in MDE — {tgt} ({uid}): {detail}"
            )
        self._log(thehive, case_id, msg)

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
        usm_result = None
        if whitelist is None:
            verdict = "true-positive"
            usm_result = self._handle_usm(thehive, case, case_id, actions)
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
            for action in actions:
                self._log_action(thehive, case_id, action)
            # Create the ticket before closing: a failed creation fails the job and leaves the case
            # open (containment has already run regardless of the ticket outcome).
            usm_result = self._handle_usm(thehive, case, case_id, actions)
            if all_succeeded:
                thehive.close_case_true_positive(case_id)
                case_closed = True
                log_message = f"{LOG_PREFIX['check']}: closed automatically as a true-positive — {base_message}"
            else:
                log_message = (
                    f"{LOG_PREFIX['check']}: true-positive, NOT closed — one or more containment actions "
                    f"failed — {base_message}"
                )
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
                "usm": usm_result,
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
