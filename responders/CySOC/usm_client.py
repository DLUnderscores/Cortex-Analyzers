#!/usr/bin/env python3
# encoding: utf-8
"""Minimal USM (Axpo service-desk) API client used by the DCSync whitelist responder.

Creates/looks-up/updates service-desk tickets. Authentication is a single ``apiKey`` header.
The create endpoint enforces a unique ``customerRef`` per ticket: an attempt to create a ticket
whose customerRef already exists returns a benign ``CustomerReference exist`` message (HTTP 2xx)
rather than an error — create_ticket reports that as ``"exists"`` so the caller can decide
whether to update the existing ticket instead.
"""
from typing import Optional
from urllib.parse import quote, urlencode

import requests

TICKET_TYPE = "Disturbance"


class USMError(Exception):
    """Raised when a USM ticket action cannot be completed."""


class USMClient:
    def __init__(self, url: str, api_key: str, http=requests, verify=True):
        self.url = url.rstrip("/")
        self.http = http
        self.verify = verify
        self.headers = {
            "apiKey": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @staticmethod
    def _extract_ticket_no(payload) -> Optional[str]:
        """Pull a ticket number out of a USM response, tolerating the shapes the API uses.

        Seen shapes:
          - create response: ``{"message": ..., "newIds": {"ticketno": ...}}`` (the new ticket's
            number is assigned under ``newIds``);
          - readall's array: ``{"object": {"objectArray": [{"ticketno": ...}]}}``;
          - plus flat (``{"ticketno": ...}``) / single-object (``{"object": {"ticketno": ...}}``)
            as defensive fallbacks.
        Returns None if no number is present.
        """
        if not isinstance(payload, dict):
            return None
        new_ids = payload.get("newIds")
        if isinstance(new_ids, dict) and new_ids.get("ticketno"):
            return new_ids["ticketno"]
        if payload.get("ticketno"):
            return payload["ticketno"]
        obj = payload.get("object")
        if isinstance(obj, dict):
            if obj.get("ticketno"):
                return obj["ticketno"]
            array = obj.get("objectArray") or []
            if array and isinstance(array[0], dict):
                return array[0].get("ticketno")
        return None

    @staticmethod
    def _json(resp, context: str) -> dict:
        """Parse a JSON body, turning a non-JSON/empty body into a clear USMError.

        requests' .json() raises a JSONDecodeError (a ValueError subclass) on an empty or
        non-JSON body — without this guard that escapes as an opaque traceback rather than the
        responder's normal error path.
        """
        try:
            return resp.json() or {}
        except ValueError as exc:
            raise USMError(
                f"{context}: HTTP {resp.status_code} with non-JSON body ({resp.text!r}) — {exc}"
            ) from exc

    def create_ticket(self, title: str, desc: str, severity_value: str, customer_ref: str) -> tuple:
        """Create a ticket. Returns ``(status, ticket_no)``.

        ``status`` is "created" on success or "exists" if the customerRef is already taken;
        ``ticket_no`` is the new ticket number when the create response carries it (the server
        assigns and echoes it on create), else None — only meaningful for "created".

        urgencyMap1 and impactMap1 are both set to severity_value (the USM severity scale).
        USM signals an already-used customerRef with a ``CustomerReference exist`` message and an
        HTTP 400 status, so the message is checked before (and independently of) the status code;
        that case is benign ("exists"), not a failure. Any other non-2xx or unrecognised response
        is an error — an uncertain creation must not be silently swallowed by a caller that fails
        only on creation errors.
        """
        body = {
            "title": title,
            "desc": desc,
            "urgencyMap1": severity_value,
            "impactMap1": severity_value,
            "type": TICKET_TYPE,
            "customerRef": customer_ref,
        }
        resp = self.http.post(
            f"{self.url}/api/create",
            headers=self.headers,
            json=body,
            verify=self.verify,
            timeout=30,
        )
        payload = self._json(resp, "Unexpected response when creating ticket")
        message = payload.get("message", "")
        if message == "CustomerReference exist":
            return "exists", None
        if not (200 <= resp.status_code < 300):
            raise USMError(f"Failed to create ticket: HTTP {resp.status_code} — {resp.text}")
        if message == "Object successfully created":
            return "created", self._extract_ticket_no(payload)
        raise USMError(f"Unexpected response when creating ticket: {message!r} — {resp.text}")

    def find_ticket_no(self, customer_ref: str) -> Optional[str]:
        """Resolve a ticket number (e.g. IN-0005702) from its customerRef, or None if not found.

        The filter query is encoded with %20 for the spaces in ``customerRef eq "..."`` rather
        than passed as a params dict: requests' form-encoding turns a space into ``+``, and the
        USM filter parser does not treat ``+`` as a space — ``customerRef+eq+"..."`` parses to
        nothing and silently returns zero matches (so the ticket number comes back as null even
        though the ticket exists). quote() gives %20 (and percent-encodes the URL value, e.g.
        ``#`` -> %23) the way the API expects.
        """
        query = urlencode({"filter": f'customerRef eq "{customer_ref}"'}, quote_via=quote)
        resp = self.http.get(
            f"{self.url}/api/readall?{query}",
            headers=self.headers,
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise USMError(f"Failed to look up ticket for {customer_ref}: HTTP {resp.status_code} — {resp.text}")
        payload = self._json(resp, f"Unexpected response when looking up ticket for {customer_ref}")
        return self._extract_ticket_no(payload)

    def update_ticket(self, ticket_no: str, desc: str, status: str = "IN_CRE") -> None:
        """Update an existing ticket's description and status."""
        resp = self.http.patch(
            f"{self.url}/api/update/{ticket_no}",
            headers=self.headers,
            json={"desc": desc, "statusOpen": status},
            verify=self.verify,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise USMError(f"Failed to update ticket {ticket_no}: HTTP {resp.status_code} — {resp.text}")
