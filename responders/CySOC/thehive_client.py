#!/usr/bin/env python3
# encoding: utf-8
"""Minimal TheHive 4 API client used by the DCSync whitelist responders."""
from typing import Optional

import requests


class TheHiveError(Exception):
    """Raised when TheHive cannot be queried."""


class TheHiveClient:
    def __init__(self, url: str, api_key: str, http=requests, verify=True):
        self.url = url.rstrip("/")
        self.http = http
        self.verify = verify
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_case_observables(self, case_id: str) -> list:
        """Return all observables of a case, including their analyzer reports."""
        body = {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "observables"},
                {"_name": "page", "from": 0, "to": 1000},
            ]
        }
        resp = self.http.post(
            f"{self.url}/api/v1/query",
            params={"name": "case-observables"},
            headers=self.headers,
            json=body,
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(f"Failed to fetch observables for case {case_id}: HTTP {resp.status_code} — {resp.text}")
        return resp.json() or []

    def close_case_false_positive(self, case_id: str) -> None:
        # No "summary" field here — the case Summary is analyst-owned; the decision is logged
        # to the Log task instead (see DCSyncWhitelistResponder._log).
        #
        # Two-PATCH approach: first close/keep-closed with {status: "Resolved"}, then set the
        # verdict with {resolutionStatus, impactStatus} in a separate request. Splitting the two
        # steps ensures that setResolutionStatus runs in its own transaction without CaseSrv's
        # closeCase PropertyUpdater prepended — which only triggers when "status": "Resolved" is
        # present in the body. This makes the verdict update work regardless of whether the case
        # was already Resolved (e.g. previously closed as TruePositive).
        for body in (
            {"status": "Resolved"},
            {"resolutionStatus": "FalsePositive", "impactStatus": "NotApplicable"},
        ):
            resp = self.http.patch(
                f"{self.url}/api/case/{case_id}",
                headers=self.headers,
                json=body,
                verify=self.verify,
                timeout=30,
            )
            if not (200 <= resp.status_code < 300):
                raise TheHiveError(f"Failed to close case {case_id} as FalsePositive: HTTP {resp.status_code} — {resp.text}")

    def close_case_true_positive(self, case_id: str) -> None:
        body = {
            "status": "Resolved",
            "resolutionStatus": "TruePositive",
            "impactStatus": "WithImpact",
        }
        resp = self.http.patch(
            f"{self.url}/api/case/{case_id}",
            headers=self.headers,
            json=body,
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(f"Failed to close case {case_id}: HTTP {resp.status_code} — {resp.text}")

    def close_case_indeterminate(self, case_id: str) -> None:
        # Same two-PATCH approach as close_case_false_positive (see its note): close with
        # {status: "Resolved"} first, then set the verdict separately so setResolutionStatus runs
        # in its own transaction regardless of the case's prior status.
        for body in (
            {"status": "Resolved"},
            {"resolutionStatus": "Indeterminate", "impactStatus": "NotApplicable"},
        ):
            resp = self.http.patch(
                f"{self.url}/api/case/{case_id}",
                headers=self.headers,
                json=body,
                verify=self.verify,
                timeout=30,
            )
            if not (200 <= resp.status_code < 300):
                raise TheHiveError(
                    f"Failed to close case {case_id} as Indeterminate: HTTP {resp.status_code} — {resp.text}"
                )

    def add_case_tags(self, case_id: str, tags: list, existing_tags=()) -> None:
        """Add tags to a case, keeping the ones it already carries.

        TheHive's case PATCH replaces the whole tag list, so the merge happens here: the caller
        passes the case's current tags (the responder is handed them with the case object).
        No-op when every tag is already present.
        """
        merged = list(existing_tags or [])
        added = [tag for tag in tags if tag not in merged]
        if not added:
            return
        resp = self.http.patch(
            f"{self.url}/api/case/{case_id}",
            headers=self.headers,
            json={"tags": merged + added},
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(
                f"Failed to tag case {case_id} with {added}: HTTP {resp.status_code} — {resp.text}"
            )

    def remove_case_tags(self, case_id: str, tags: list, existing_tags=()) -> None:
        """Remove tags from a case, keeping every other tag it carries.

        Same mechanics as add_case_tags — the PATCH replaces the whole list, so the caller passes
        the case's current tags. No-op when none of them is present.
        """
        current = list(existing_tags or [])
        removed = [tag for tag in tags if tag in current]
        if not removed:
            return
        resp = self.http.patch(
            f"{self.url}/api/case/{case_id}",
            headers=self.headers,
            json={"tags": [tag for tag in current if tag not in removed]},
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(
                f"Failed to remove tag(s) {removed} from case {case_id}: HTTP {resp.status_code} — {resp.text}"
            )

    def get_case_tasks(self, case_id: str) -> list:
        """Return all tasks of a case."""
        body = {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "tasks"},
                {"_name": "page", "from": 0, "to": 1000},
            ]
        }
        resp = self.http.post(
            f"{self.url}/api/v1/query",
            params={"name": "case-tasks"},
            headers=self.headers,
            json=body,
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(f"Failed to fetch tasks for case {case_id}: HTTP {resp.status_code} — {resp.text}")
        return resp.json() or []

    def _complete_task(self, task_id: str) -> None:
        """Drive a task to "Completed" — it's a log, not a checklist item, so it's never left open."""
        for status in ("InProgress", "Completed"):
            self.http.patch(
                f"{self.url}/api/case/task/{task_id}",
                headers=self.headers,
                json={"status": status},
                verify=self.verify,
                timeout=30,
            )

    def create_task(self, case_id: str, title: str, group: str) -> str:
        resp = self.http.post(
            f"{self.url}/api/case/{case_id}/task",
            headers=self.headers,
            json={"title": title, "group": group},
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(
                f"Failed to create task '{title}' for case {case_id}: HTTP {resp.status_code} — {resp.text}"
            )
        task = resp.json()
        task_id = task.get("_id") or task.get("id")
        self._complete_task(task_id)
        return task_id

    def get_or_create_task(self, case_id: str, group: str, title: str) -> str:
        for task in self.get_case_tasks(case_id):
            if task.get("group") == group and task.get("title") == title:
                task_id = task.get("_id") or task.get("id")
                if task.get("status") != "Completed":
                    self._complete_task(task_id)
                return task_id
        return self.create_task(case_id, title, group)

    def add_task_log(self, task_id: str, message: str) -> None:
        resp = self.http.post(
            f"{self.url}/api/case/task/{task_id}/log",
            headers=self.headers,
            json={"message": message},
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(f"Failed to write log to task {task_id}: HTTP {resp.status_code} — {resp.text}")

    def get_last_task_log_message(self, task_id: str) -> Optional[str]:
        body = {
            "query": [
                {"_name": "getTask", "idOrName": task_id},
                {"_name": "logs"},
                {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                {"_name": "page", "from": 0, "to": 1},
            ]
        }
        resp = self.http.post(
            f"{self.url}/api/v1/query",
            params={"name": "task-logs"},
            headers=self.headers,
            json=body,
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise TheHiveError(f"Failed to fetch logs for task {task_id}: HTTP {resp.status_code} — {resp.text}")
        entries = resp.json() or []
        return entries[0].get("message") if entries else None

    def log_to_task(self, case_id: str, group: str, title: str, message: str, dedup: bool = True) -> None:
        """Find-or-create the (group, title) task on the case and append a log entry to it.

        When dedup=True (default), skipped if the message is an exact duplicate of the task's most
        recent entry — prevents re-running a job with the same outcome from repeating the same line.
        Pass dedup=False for all entries after the first in a single run: the first entry guards
        against repeating the run-level verdict, while subsequent per-action entries should always
        be written regardless.
        """
        task_id = self.get_or_create_task(case_id, group, title)
        if dedup and self.get_last_task_log_message(task_id) == message:
            return
        self.add_task_log(task_id, message)
