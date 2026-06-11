#!/usr/bin/env python3
# encoding: utf-8
"""Minimal TheHive 4 API client used by the DCSync whitelist responders."""
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

    def close_case_false_positive(self, case_id: str, summary: str) -> None:
        body = {
            "status": "Resolved",
            "resolutionStatus": "FalsePositive",
            "impactStatus": "NotApplicable",
            "summary": summary,
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
