#!/usr/bin/env python3
# encoding: utf-8
import re
import traceback
from typing import Optional

import requests
from cortexutils.analyzer import Analyzer

MDE_BASE_URL = "https://api.securitycenter.microsoft.com/api/"
MDE_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"

# Microsoft 365 Defender (unified) — required for cross-product tables like IdentityInfo
M365_BASE_URL = "https://api.security.microsoft.com/api/"
M365_SCOPE = "https://api.security.microsoft.com/.default"

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
SID_RE = re.compile(r"^S-1-5-\d+(?:-\d+)+$", re.I)

RISK_LEVEL_MAP = {
    "critical": "malicious",
    "high": "malicious",
    "medium": "suspicious",
    "low": "info",
    "none": "safe",
    "unknown": "safe",
}


class MicrosoftDefenderAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.tenant_id = self.get_param("config.tenant_id", None, "MDE Tenant ID is missing")
        self.client_id = self.get_param("config.client_id", None, "MDE Client ID is missing")
        self.client_secret = self.get_param("config.client_secret", None, "MDE Client Secret is missing")
        self._token: Optional[str] = None
        self._m365_token: Optional[str] = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        if self._token is not None:
            return self._token
        self._token = self._fetch_token(MDE_SCOPE)
        return self._token

    def _get_m365_token(self) -> str:
        if self._m365_token is not None:
            return self._m365_token
        self._m365_token = self._fetch_token(M365_SCOPE)
        return self._m365_token

    def _fetch_token(self, scope: str) -> str:
        url = MDE_TOKEN_URL.format(tenant_id=self.tenant_id)
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": scope,
        }
        resp = requests.post(url, data=payload, timeout=30)
        if resp.status_code != 200:
            self.error(f"OAuth2 token request failed for {scope} (HTTP {resp.status_code}): {resp.text}")
        token = resp.json().get("access_token")
        if not token:
            self.error(f"OAuth2 response contained no access_token for {scope}")
        return token

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
            "User-Agent": "strangebee-thehive/1.0",
        }

    def _get(self, path: str, params: dict = None) -> dict:
        resp = requests.get(MDE_BASE_URL + path, headers=self._headers(), params=params, timeout=30)
        if not (200 <= resp.status_code < 300):
            self.error(f"MDE API error on {path}: HTTP {resp.status_code} — {resp.text}")
        return resp.json()

    def _get_optional(self, path: str, params: dict = None) -> dict:
        """Like _get but returns {} on any non-2xx without failing the analysis."""
        try:
            resp = requests.get(MDE_BASE_URL + path, headers=self._headers(), params=params, timeout=30)
            if 200 <= resp.status_code < 300:
                return resp.json()
        except Exception:
            pass
        return {}

    def _post_optional(self, path: str, body: dict) -> dict:
        """POST to MDE API, returns {} on any failure without failing the analysis."""
        try:
            headers = {**self._headers(), "Content-Type": "application/json"}
            resp = requests.post(MDE_BASE_URL + path, headers=headers, json=body, timeout=30)
            if 200 <= resp.status_code < 300:
                return resp.json()
        except Exception:
            pass
        return {}

    def _post_m365_optional(self, path: str, body: dict) -> dict:
        """POST to M365 Defender API (supports cross-product tables like IdentityInfo)."""
        try:
            headers = {
                "Authorization": f"Bearer {self._get_m365_token()}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "strangebee-thehive/1.0",
            }
            resp = requests.post(M365_BASE_URL + path, headers=headers, json=body, timeout=30)
            if 200 <= resp.status_code < 300:
                return resp.json()
        except Exception:
            pass
        return {}

    # ------------------------------------------------------------------
    # Device search strategies
    # ------------------------------------------------------------------

    def _search_machine(self, observable: str) -> dict:
        safe = observable.lower().replace("'", "''")
        is_ip = bool(IPV4_RE.match(observable)) or self.data_type == "ip"
        is_short = ("." not in observable) and not is_ip

        # Strategy 1: exact computerDnsName match
        data = self._get("machines", params={"$filter": f"computerDnsName eq '{safe}'"})
        machines = data.get("value", [])
        if machines:
            return machines[0]

        # Strategy 2: lastIpAddress match (IP inputs)
        if is_ip:
            data = self._get("machines", params={"$filter": f"lastIpAddress eq '{safe}'"})
            machines = data.get("value", [])
            if machines:
                return machines[0]

        # Strategy 3: startswith match for short hostnames
        if is_short:
            data = self._get("machines", params={"$filter": f"startswith(computerDnsName,'{safe}')"})
            machines = data.get("value", [])
            if machines:
                return machines[0]

        self.error(f"No device found in MDE for observable: {observable}")

    # ------------------------------------------------------------------
    # Supplementary data fetchers (graceful degradation on failure)
    # ------------------------------------------------------------------

    def _get_device_info(self, machine_id: str) -> dict:
        """Fetch DeviceType, DeviceCategory and Tags via Advanced Hunting (requires AdvancedQuery.Read.All)."""
        safe_id = machine_id.replace("'", "''")
        query = f"DeviceInfo | where DeviceId == '{safe_id}' | project DeviceType, DeviceSubtype, DeviceDynamicTags | take 1"
        try:
            headers = {**self._headers(), "Content-Type": "application/json"}
            resp = requests.post(MDE_BASE_URL + "advancedqueries/run", headers=headers, json={"Query": query}, timeout=30)
            if 200 <= resp.status_code < 300:
                rows = resp.json().get("Results", [])
                return rows[0] if rows else {}
            return {"_error": f"HTTP {resp.status_code}", "_body": resp.text[:500]}
        except Exception as e:
            return {"_error": str(e)}

    def _get_alerts(self, machine_id: str) -> list:
        data = self._get_optional(f"machines/{machine_id}/alerts", params={"$filter": "status ne 'Resolved'"})
        return data.get("value", [])

    def _get_logon_users(self, machine_id: str) -> list:
        data = self._get_optional(f"machines/{machine_id}/logonusers")
        return data.get("value", [])

    # ------------------------------------------------------------------
    # User search strategies
    # ------------------------------------------------------------------

    def _search_user(self, observable: str) -> dict:
        """Find user via IdentityInfo in the M365 Defender API (cross-product hunting, supports IdentityInfo).

        Resolves by the most specific identifier the observable looks like, then falls back to
        broader keys. On-prem-only accounts (e.g. AAD Connect service accounts) are frequently
        absent from IdentityInfo under AccountName, but are resolvable by their on-prem SID or
        on-prem AD object GUID — the identifiers MDI alert evidence carries as user_sid /
        activeDirectoryObjectGuid. Each candidate runs as its own query so a column missing from a
        given IdentityInfo schema version only drops that fallback instead of failing the lookup.
        """
        safe = observable.replace("'", "''")
        if SID_RE.match(observable):
            # On-prem AD SID (the user_sid from MDI alert evidence)
            clauses = [f"OnPremSid =~ '{safe}'"]
        elif GUID_RE.match(observable):
            # A GUID may be an Entra object id (AccountObjectId) or an on-prem AD object GUID
            # (OnPremObjectId — what MDI alert evidence exposes as activeDirectoryObjectGuid).
            clauses = [f"AccountObjectId =~ '{safe}'", f"OnPremObjectId =~ '{safe}'"]
        elif "@" in observable:
            clauses = [f"AccountUpn =~ '{safe}'", f"EmailAddress =~ '{safe}'"]
        else:
            # A bare name: exact SAM/AccountName first, then broaden to the other name columns the
            # same identity may be indexed under (UPN local part, display name). On-prem service
            # accounts often sit in IdentityInfo under a name other than the SAM the alert reports.
            clauses = [
                f"AccountName =~ '{safe}'",
                f"AccountUpn startswith '{safe}@'",
                f"AccountDisplayName =~ '{safe}'",
            ]
        for clause in clauses:
            query = f"IdentityInfo | where {clause} | sort by Timestamp desc | take 1"
            rows = self._post_m365_optional("advancedhunting/run", {"Query": query}).get("Results", [])
            if rows:
                return rows[0]
        self.error(f"No user found in MDE for observable: {observable}")

    def _get_user_alerts(self, account_name: str) -> list:
        data = self._get_optional(f"users/{account_name}/alerts", params={"$filter": "status ne 'Resolved'"})
        return data.get("value", [])

    def _get_user_machines(self, account_name: str) -> list:
        data = self._get_optional(f"users/{account_name}/machines")
        return data.get("value", [])

    # ------------------------------------------------------------------
    # Cortex entry points
    # ------------------------------------------------------------------

    def run(self):
        Analyzer.run(self)
        try:
            observable = self.get_data().strip()
            if self.data_type in ("hostname", "fqdn", "ip"):
                machine = self._search_machine(observable)
                machine_id = machine["id"]
                device_info = self._get_device_info(machine_id)
                alerts = self._get_alerts(machine_id)
                logon_users = self._get_logon_users(machine_id)
                self.report({
                    "machine": machine,
                    "device_info": device_info,
                    "alerts": alerts,
                    "logon_users": logon_users,
                    "active_alerts_count": len(alerts),
                })
            elif self.data_type in ("mail", "username"):
                user = self._search_user(observable)
                account_name = user.get("AccountName", "")
                alerts = self._get_user_alerts(account_name)
                machines = self._get_user_machines(account_name)
                self.report({
                    "user": user,
                    "alerts": alerts,
                    "machines": machines,
                    "active_alerts_count": len(alerts),
                    "tenant_id": self.tenant_id,
                })
            else:
                self.notSupported()
        except SystemExit:
            raise
        except Exception:
            self.unexpectedError(traceback.format_exc())

    def summary(self, raw):
        taxonomies = []
        namespace = "MDE"

        def risk_level(value: str) -> str:
            return RISK_LEVEL_MAP.get((value or "none").lower(), "safe")

        def add(predicate, value, level="info"):
            if value is not None and str(value) != "":
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, str(value)))

        machine = raw.get("machine", {})
        user = raw.get("user", {})

        if machine:
            device_info = raw.get("device_info", {})

            # Device ID
            add("Device_ID", machine.get("id"))

            # Color-coded risk/exposure
            risk = machine.get("riskScore", "none")
            add("Risk_Level", risk or "none", risk_level(risk))

            exposure = machine.get("exposureLevel", "none")
            add("Exposure_Level", exposure or "none", risk_level(exposure))

            # OS
            os_parts = [p for p in [machine.get("osPlatform"), str(machine.get("osBuild", "") or "")] if p]
            add("OS", " ".join(os_parts) if os_parts else None)

            # SAM name (short hostname)
            dns_name = machine.get("computerDnsName", "")
            add("SAM_Name", dns_name.split(".")[0] if dns_name else None)

            # Domain
            add("Domain", machine.get("rbacGroupName") or machine.get("domainName"))

            # Device type — from Advanced Hunting DeviceInfo table
            add("Device_Type", device_info.get("DeviceType"))
            subtype = device_info.get("DeviceSubtype")
            if subtype and subtype != device_info.get("DeviceType"):
                add("Device_Subtype", subtype)
            dynamic_tags = device_info.get("DeviceDynamicTags")
            if dynamic_tags:
                val = ", ".join(dynamic_tags) if isinstance(dynamic_tags, list) else str(dynamic_tags)
                add("Device_Tags", val)

            # Device health and onboarding
            add("Health_Status", machine.get("healthStatus"))
            add("Onboarding_Status", machine.get("onboardingStatus"))

            # Timestamps
            add("First_Seen", machine.get("firstSeen"))
            add("Last_Seen", machine.get("lastSeen"))

            add("Last_Internal_IP", machine.get("lastIpAddress"))
            add("Last_External_IP", machine.get("lastExternalIpAddress"))

            # MAC address — MDE returns without separators, insert colons
            mac_raw = machine.get("macAddress", "") or ""
            if len(mac_raw) >= 2:
                mac_fmt = ":".join(mac_raw[i:i + 2] for i in range(0, len(mac_raw), 2))
                add("MAC_Address", mac_fmt)

        elif user:
            add("UPN", user.get("AccountUpn"))
            add("Display_Name", user.get("AccountDisplayName"))
            add("Account_Domain", user.get("AccountDomain"))
            add("Account_Object_ID", user.get("AccountObjectId"))
            add("OnPrem_Object_ID", user.get("OnPremObjectId"))
            # Defender identity-account id — the trailing GUID of IdentityId (User_<tenant>_<id>).
            # This is the path id required by the identityAccounts invokeAction endpoint, used by the
            # DCSync responder to force a password reset on hybrid/on-prem-mastered accounts.
            identity_id = user.get("IdentityId", "") or ""
            id_tail = identity_id.rsplit("_", 1)[-1] if "_" in identity_id else ""
            if GUID_RE.match(id_tail):
                add("Identity_Account_ID", id_tail)
            add("Department", user.get("Department"))
            add("Job_Title", user.get("JobTitle"))

            enabled = user.get("IsAccountEnabled")
            if enabled is not None:
                add("Account_Enabled", "Yes" if enabled else "No", "safe" if enabled else "warning")

            risk_score = user.get("RiskScore")
            if risk_score is not None:
                rs_level = "malicious" if risk_score > 80 else "suspicious" if risk_score > 50 else "info"
                add("Risk_Score", risk_score, rs_level)

            criticality = user.get("CriticalityLevel")
            if criticality:
                crit_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
                crit_level = "malicious" if criticality >= 3 else "suspicious" if criticality == 2 else "info"
                add("Criticality", crit_map.get(criticality, str(criticality)), crit_level)

            tags = user.get("Tags")
            if tags:
                val = ", ".join(tags) if isinstance(tags, list) else str(tags)
                add("Tags", val)

            add("Machine_Count", len(raw.get("machines", [])))

        # Active alerts — color coded (shared between device and user paths)
        alert_count = raw.get("active_alerts_count", 0)
        alert_level = "malicious" if alert_count > 5 else "suspicious" if alert_count > 0 else "safe"
        taxonomies.append(self.build_taxonomy(alert_level, namespace, "Active_Alerts", alert_count))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        input_lower = self.get_data().strip().lower()
        machine = raw.get("machine", {})
        user = raw.get("user", {})

        if machine:
            # All IPs → new ip observables
            ip_set = set()
            if machine.get("lastIpAddress"):
                ip_set.add(machine["lastIpAddress"])
            for entry in machine.get("ipAddresses", []):
                ip = entry.get("ipAddress", "")
                if ip:
                    ip_set.add(ip)

            dns_name = machine.get("computerDnsName", "")
            for ip in ip_set:
                if ip.lower() != input_lower:
                    artifacts.append(self.build_artifact("ip", ip, tags=["MicrosoftDefender", f"device={dns_name}"]))

            # Full FQDN → fqdn observable
            if dns_name and "." in dns_name and dns_name.lower() != input_lower:
                artifacts.append(self.build_artifact("fqdn", dns_name, tags=["MicrosoftDefender"]))

            # Logged-on users → mail observables
            for logon_user in raw.get("logon_users", []):
                account = logon_user.get("accountName", "")
                domain = logon_user.get("domainName", "")
                if account and domain:
                    artifacts.append(
                        self.build_artifact("mail", f"{account}@{domain}", tags=["MicrosoftDefender", "logon_user"])
                    )

        elif user:
            account_name = user.get("AccountName", "")

            # UPN → mail observable (when input is not already a mail)
            upn = user.get("AccountUpn", "")
            if upn and self.data_type != "mail" and upn.lower() != input_lower:
                artifacts.append(self.build_artifact("mail", upn, tags=["MicrosoftDefender"]))

            # AccountName → username observable (when input is not already a username)
            if account_name and self.data_type != "username" and account_name.lower() != input_lower:
                artifacts.append(self.build_artifact("username", account_name, tags=["MicrosoftDefender"]))

            # Associated machine FQDNs → fqdn observables
            for m in raw.get("machines", []):
                dns_name = m.get("computerDnsName", "")
                if dns_name and "." in dns_name:
                    artifacts.append(
                        self.build_artifact("fqdn", dns_name, tags=["MicrosoftDefender", f"user={account_name}"])
                    )

        return artifacts


if __name__ == "__main__":
    MicrosoftDefenderAnalyzer().run()
