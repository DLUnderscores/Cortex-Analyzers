import json

import pytest

from dcsync_whitelist import DCSyncWhitelistResponder
from defender_client import DefenderActionError
from whitelist import pair_key

USER_GUID = "11111111-2222-3333-4444-555555555555"
DEVICE_ID = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
PAIR_KEY = pair_key(USER_GUID, DEVICE_ID)
USER1_GUID = "22222222-2222-2222-2222-222222222222"
USER2_GUID = "33333333-3333-3333-3333-333333333333"
LAB1_DEVICE_ID = "b" * 40

CASE = {
    "_id": "~4128",
    "caseId": 42,
    "title": "DCSync attack detected",
    "owner": "analyst@socdev.lan",
}

OBSERVABLES = [
    {
        "dataType": "hostname",
        "data": "ws01.socdev.lan",
        "tags": [],
        "reports": {
            "MicrosoftDefender_GetDeviceInfo_1_0": {"taxonomies": [{"predicate": "Device_ID", "value": DEVICE_ID}]}
        },
    },
    {
        "dataType": "username",
        "data": "svc-sync",
        "tags": [],
        "reports": {
            "MicrosoftDefender_GetUserInfo_1_0": {"taxonomies": [{"predicate": "Account_Object_ID", "value": USER_GUID}]}
        },
    },
]


class StubTheHive:
    def __init__(self, observables):
        self.observables = observables
        self.closed = []  # (case_id, verdict)
        self.logs = []  # (case_id, group, title, message)

    def get_case_observables(self, case_id):
        return self.observables

    def close_case_false_positive(self, case_id):
        self.closed.append((case_id, "false-positive"))

    def close_case_true_positive(self, case_id):
        self.closed.append((case_id, "true-positive"))

    def log_to_task(self, case_id, group, title, message, dedup=True):
        self.logs.append((case_id, group, title, message))


class StubWhitelist:
    def __init__(self, entries=None):
        self.stored = dict(entries or {})
        self.writes = []

    def entries(self):
        return dict(self.stored)

    def put(self, key, metadata):
        self.writes.append((key, metadata))
        self.stored[key] = metadata


class StubDefender:
    def __init__(self, fail_users=(), fail_devices=()):
        self.disabled = []
        self.password_resets = []
        self.revoked = []
        self.isolated = []  # (device_id, full)
        self.fail_users = set(fail_users)
        self.fail_devices = set(fail_devices)

    def disable_user(self, user_id):
        if user_id in self.fail_users:
            raise DefenderActionError(f"failed to disable {user_id}")
        self.disabled.append(user_id)

    def force_password_reset(self, user_id):
        if user_id in self.fail_users:
            raise DefenderActionError(f"failed to reset password for {user_id}")
        self.password_resets.append(user_id)

    def revoke_sessions(self, user_id):
        if user_id in self.fail_users:
            raise DefenderActionError(f"failed to revoke sessions for {user_id}")
        self.revoked.append(user_id)

    def isolate_device(self, device_id, comment, full=False):
        if device_id in self.fail_devices:
            raise DefenderActionError(f"failed to isolate {device_id}")
        self.isolated.append((device_id, full))


class ResponderUnderTest(DCSyncWhitelistResponder):
    def __init__(self, job_directory, thehive, whitelist, defender=None):
        self.stub_thehive = thehive
        self.stub_whitelist = whitelist
        self.stub_defender = defender
        super().__init__(job_directory=str(job_directory))

    def _thehive(self):
        return self.stub_thehive

    def _whitelist(self):
        return self.stub_whitelist

    def _defender(self):
        return self.stub_defender


def write_job(tmp_path, service, case=CASE, config_overrides=None):
    config = {
        "service": service,
        "thehive_url": "http://thehive",
        "thehive_api_key": "key",
        "consul_url": "http://consul:8500",
        "consul_kv_whitelist": "cysoc/office/sirp/dcsync/whitelist",
    }
    config.update(config_overrides or {})
    (tmp_path / "input").mkdir()
    (tmp_path / "input" / "input.json").write_text(
        json.dumps({"dataType": "thehive:case", "tlp": 2, "pap": 2, "data": case, "config": config})
    )
    return tmp_path


def read_output(tmp_path):
    return json.loads((tmp_path / "output" / "output.json").read_text())


def run_responder(tmp_path, thehive, whitelist, defender=None):
    responder = ResponderUnderTest(tmp_path, thehive, whitelist, defender)
    responder.run()
    return read_output(tmp_path)


def two_user_one_host_observables():
    """user1@lab1 and user2@lab1 — used to test that only the non-whitelisted pair is acted on."""
    host = {
        "dataType": "hostname",
        "data": "lab1",
        "tags": [],
        "reports": {"MicrosoftDefender_GetDeviceInfo_1_0": {"taxonomies": [{"predicate": "Device_ID", "value": LAB1_DEVICE_ID}]}},
    }
    user1 = {
        "dataType": "username",
        "data": "user1",
        "tags": [],
        "reports": {
            "MicrosoftDefender_GetUserInfo_1_0": {"taxonomies": [{"predicate": "Account_Object_ID", "value": USER1_GUID}]}
        },
    }
    user2 = {
        "dataType": "username",
        "data": "user2",
        "tags": [],
        "reports": {
            "MicrosoftDefender_GetUserInfo_1_0": {"taxonomies": [{"predicate": "Account_Object_ID", "value": USER2_GUID}]}
        },
    }
    return [host, user1, user2]


def test_check_all_pairs_whitelisted_closes_case_as_fp(tmp_path):
    write_job(tmp_path, "check")
    thehive = StubTheHive(OBSERVABLES)
    output = run_responder(tmp_path, thehive, StubWhitelist({PAIR_KEY: {"account": "svc-sync"}}))

    assert output["success"] is True
    assert output["full"]["verdict"] == "false-positive"
    assert output["full"]["case_closed"] is True
    assert thehive.closed[0] == ("~4128", "false-positive")
    assert thehive.logs[0][1:3] == ("CySOC", "Log")
    assert thehive.logs[0][3].startswith("CySOC_DCSync_Respond:")
    assert "false-positive" in thehive.logs[0][3]


def test_check_fp_without_closing_when_disabled(tmp_path):
    write_job(tmp_path, "check", config_overrides={"close_on_fp": False})
    thehive = StubTheHive(OBSERVABLES)
    output = run_responder(tmp_path, thehive, StubWhitelist({PAIR_KEY: {}}))

    assert output["full"]["verdict"] == "false-positive"
    assert output["full"]["case_closed"] is False
    assert thehive.closed == []


def test_check_unknown_pair_is_true_positive(tmp_path):
    write_job(tmp_path, "check")
    thehive = StubTheHive(OBSERVABLES)
    output = run_responder(tmp_path, thehive, StubWhitelist())

    assert output["full"]["verdict"] == "true-positive"
    assert output["full"]["unmatched"][0]["key"] == PAIR_KEY
    assert output["full"]["case_closed"] is True
    assert thehive.closed[0] == ("~4128", "true-positive")
    assert "not found in the whitelist" in thehive.logs[0][3]


def test_check_treats_missing_whitelist_config_as_not_whitelisted(tmp_path):
    write_job(tmp_path, "check", config_overrides={"consul_kv_whitelist": ""})
    thehive = StubTheHive(OBSERVABLES)
    # stub has the pair whitelisted, but it must never be consulted without a configured key
    output = run_responder(tmp_path, thehive, StubWhitelist({PAIR_KEY: {"account": "svc-sync"}}))

    assert output["full"]["verdict"] == "true-positive"
    assert output["full"]["whitelist_configured"] is False
    assert output["full"]["case_closed"] is False
    assert thehive.closed == []
    assert "not configured" in thehive.logs[0][3]


def test_update_requires_whitelist_config(tmp_path):
    write_job(tmp_path, "update", config_overrides={"consul_kv_whitelist": ""})
    thehive = StubTheHive(OBSERVABLES)

    with pytest.raises(SystemExit):
        run_responder(tmp_path, thehive, StubWhitelist())

    output = read_output(tmp_path)
    assert output["success"] is False
    assert "Consul KV whitelist key is missing" in output["errorMessage"]
    assert "FAILED" in thehive.logs[0][3]
    assert "Consul KV whitelist key is missing" in thehive.logs[0][3]


def test_check_fails_safe_on_observable_without_enrichment(tmp_path):
    write_job(tmp_path, "check")
    observables = [{"dataType": "hostname", "data": "ghost", "tags": [], "reports": {}}, OBSERVABLES[1]]
    thehive = StubTheHive(observables)
    whitelist = StubWhitelist({PAIR_KEY: {}})

    with pytest.raises(SystemExit):
        run_responder(tmp_path, thehive, whitelist)

    output = read_output(tmp_path)
    assert output["success"] is False
    assert "unresolved" in output["errorMessage"]
    assert thehive.closed == []
    assert "FAILED" in thehive.logs[0][3]
    assert "unresolved" in thehive.logs[0][3]


def test_no_case_id_fails_without_logging(tmp_path):
    write_job(tmp_path, "check", case={"caseId": 1, "title": "no id"})
    thehive = StubTheHive(OBSERVABLES)

    with pytest.raises(SystemExit):
        run_responder(tmp_path, thehive, StubWhitelist())

    assert read_output(tmp_path)["success"] is False
    assert thehive.logs == []  # no case id known yet — nothing to log against


def test_unexpected_error_is_logged_to_task(tmp_path):
    write_job(tmp_path, "check")

    class BrokenTheHive(StubTheHive):
        def get_case_observables(self, case_id):
            raise RuntimeError("boom")

    thehive = BrokenTheHive(OBSERVABLES)

    with pytest.raises(SystemExit):
        run_responder(tmp_path, thehive, StubWhitelist())

    output = read_output(tmp_path)
    assert output["success"] is False
    assert "FAILED" in thehive.logs[0][3]
    assert "boom" in thehive.logs[0][3]


def test_check_containment_actions_only_target_non_whitelisted_pair(tmp_path):
    write_job(
        tmp_path,
        "check",
        config_overrides={
            "disable_user_on_tp": True,
            "force_password_reset_on_tp": True,
            "revoke_sessions_on_tp": True,
            "isolate_device_on_tp": True,
            "tenant_id": "t",
            "client_id": "c",
            "client_secret": "s",
        },
    )
    thehive = StubTheHive(two_user_one_host_observables())
    whitelist = StubWhitelist({pair_key(USER1_GUID, LAB1_DEVICE_ID): {"account": "user1"}})
    defender = StubDefender()

    output = run_responder(tmp_path, thehive, whitelist, defender)

    assert output["full"]["verdict"] == "true-positive"
    assert output["full"]["case_closed"] is True
    assert defender.disabled == [USER2_GUID]
    assert defender.password_resets == [USER2_GUID]
    assert defender.revoked == [USER2_GUID]
    assert defender.isolated == [(LAB1_DEVICE_ID, False)]
    assert thehive.closed[0] == ("~4128", "true-positive")
    log_messages = [entry[3] for entry in thehive.logs]
    assert any("account disabled in Entra" in m and "user2" in m for m in log_messages)
    assert any("password reset forced in Entra" in m and "user2" in m for m in log_messages)
    assert any("sign-in sessions revoked in Entra" in m and "user2" in m for m in log_messages)
    assert any("device isolated (Selective) in MDE" in m and "lab1" in m for m in log_messages)
    assert any("closed automatically as a true-positive" in m for m in log_messages)
    assert not any("user1" in m for m in log_messages)  # whitelisted user must never appear


def test_check_case_not_closed_when_an_action_fails(tmp_path):
    write_job(
        tmp_path,
        "check",
        config_overrides={"disable_user_on_tp": True, "tenant_id": "t", "client_id": "c", "client_secret": "s"},
    )
    thehive = StubTheHive(two_user_one_host_observables())
    whitelist = StubWhitelist({pair_key(USER1_GUID, LAB1_DEVICE_ID): {"account": "user1"}})
    defender = StubDefender(fail_users=[USER2_GUID])

    output = run_responder(tmp_path, thehive, whitelist, defender)

    assert output["full"]["verdict"] == "true-positive"
    assert output["full"]["case_closed"] is False
    assert thehive.closed == []
    log_messages = [entry[3] for entry in thehive.logs]
    # action failure has its own log entry
    assert any("FAILED to disable account in Entra" in m and "user2" in m for m in log_messages)
    # verdict entry says case not closed
    assert any("NOT closed" in m for m in log_messages)


def test_check_graph_actions_skipped_for_onprem_only_id(tmp_path):
    write_job(
        tmp_path,
        "check",
        config_overrides={
            "disable_user_on_tp": True,
            "force_password_reset_on_tp": True,
            "revoke_sessions_on_tp": True,
            "tenant_id": "t",
            "client_id": "c",
            "client_secret": "s",
        },
    )
    onprem_obs = [
        OBSERVABLES[0],
        {
            "dataType": "username",
            "data": "svc-sync",
            "tags": [],
            "reports": {
                "MicrosoftDefender_GetUserInfo_1_0": {
                    "taxonomies": [{"predicate": "OnPrem_Object_ID", "value": USER_GUID}]
                }
            },
        },
    ]
    thehive = StubTheHive(onprem_obs)
    defender = StubDefender()

    output = run_responder(tmp_path, thehive, StubWhitelist(), defender)

    assert output["full"]["case_closed"] is False
    assert defender.disabled == []
    assert defender.password_resets == []
    assert defender.revoked == []
    # all three Graph actions should be recorded as failures (one per action type)
    failed = [a for a in output["full"]["actions"] if not a["success"]]
    assert len(failed) == 3
    assert all("on-prem" in a["detail"] for a in failed)
    log_messages = [entry[3] for entry in thehive.logs]
    assert any("FAILED to disable account in Entra" in m for m in log_messages)
    assert any("FAILED to force password reset in Entra" in m for m in log_messages)
    assert any("FAILED to revoke sign-in sessions in Entra" in m for m in log_messages)
    assert any("NOT closed" in m for m in log_messages)


def test_check_user_iterated_once_per_action_type(tmp_path):
    # Two users paired with the same host — both should be acted on exactly once per action, not once per pair.
    write_job(
        tmp_path,
        "check",
        config_overrides={
            "disable_user_on_tp": True,
            "force_password_reset_on_tp": True,
            "revoke_sessions_on_tp": True,
            "tenant_id": "t",
            "client_id": "c",
            "client_secret": "s",
        },
    )
    thehive = StubTheHive(two_user_one_host_observables())
    defender = StubDefender()

    run_responder(tmp_path, thehive, StubWhitelist(), defender)

    # Both users present, acted on exactly once each per action type
    assert sorted(defender.disabled) == sorted([USER1_GUID, USER2_GUID])
    assert sorted(defender.password_resets) == sorted([USER1_GUID, USER2_GUID])
    assert sorted(defender.revoked) == sorted([USER1_GUID, USER2_GUID])


def test_check_requires_defender_credentials_when_action_enabled(tmp_path):
    write_job(tmp_path, "check", config_overrides={"disable_user_on_tp": True})
    thehive = StubTheHive(OBSERVABLES)

    with pytest.raises(SystemExit):
        run_responder(tmp_path, thehive, StubWhitelist())

    output = read_output(tmp_path)
    assert output["success"] is False
    assert "tenant_id" in output["errorMessage"]


def test_check_fails_safe_when_no_pair_found(tmp_path):
    write_job(tmp_path, "check")
    thehive = StubTheHive([OBSERVABLES[0]])  # host only, no user observable

    with pytest.raises(SystemExit):
        run_responder(tmp_path, thehive, StubWhitelist())

    assert read_output(tmp_path)["success"] is False
    assert thehive.closed == []


def test_update_adds_pair_with_metadata(tmp_path):
    write_job(tmp_path, "update")
    whitelist = StubWhitelist()
    thehive = StubTheHive(OBSERVABLES)
    output = run_responder(tmp_path, thehive, whitelist)

    assert output["full"]["added"][0]["key"] == PAIR_KEY
    assert output["full"]["already_present"] == []
    key, metadata = whitelist.writes[0]
    assert key == PAIR_KEY
    assert metadata["account"] == "svc-sync"
    assert metadata["hostname"] == "ws01.socdev.lan"
    assert metadata["added_by"] == "analyst@socdev.lan"
    assert metadata["case_number"] == 42
    assert output["full"]["case_closed"] is True
    assert thehive.closed[0] == ("~4128", "false-positive")
    assert thehive.logs[0][1:3] == ("CySOC", "Log")
    assert thehive.logs[0][3].startswith("CySOC_DCSync_UpdateWhitelist:")
    assert "case #" not in thehive.logs[0][3]
    assert "added to whitelist" in thehive.logs[0][3]
    assert "case closed as false-positive" in thehive.logs[0][3]


def test_update_is_idempotent(tmp_path):
    write_job(tmp_path, "update")
    whitelist = StubWhitelist({PAIR_KEY: {"account": "svc-sync"}})
    thehive = StubTheHive(OBSERVABLES)
    output = run_responder(tmp_path, thehive, whitelist)

    assert output["full"]["added"] == []
    assert output["full"]["already_present"][0]["key"] == PAIR_KEY
    assert len(whitelist.writes) == 1  # metadata refreshed in place
    assert thehive.closed[0] == ("~4128", "false-positive")


def role_tagged_observables():
    source_host = {**OBSERVABLES[0], "tags": ["mde:role=source"]}
    source_user = {**OBSERVABLES[1], "tags": ["mde:role=source"]}
    destination_host = {
        "dataType": "hostname",
        "data": "dc01.socdev.lan",
        "tags": ["mde:role=destination"],
        "reports": {
            "MicrosoftDefender_GetDeviceInfo_1_0": {"taxonomies": [{"predicate": "Device_ID", "value": "f" * 40}]}
        },
    }
    return [source_host, destination_host, source_user]


def test_check_uses_only_source_role_tagged_pair(tmp_path):
    write_job(tmp_path, "check")
    thehive = StubTheHive(role_tagged_observables())
    # only the source pair is whitelisted; the destination DC pair is not
    output = run_responder(tmp_path, thehive, StubWhitelist({PAIR_KEY: {"account": "svc-sync"}}))

    assert output["full"]["pair_selection"] == "source-role-tags"
    assert output["full"]["pairs_evaluated"] == 1
    assert output["full"]["verdict"] == "false-positive"
    assert output["full"]["case_closed"] is True


def test_update_writes_only_source_pair(tmp_path):
    write_job(tmp_path, "update")
    whitelist = StubWhitelist()
    output = run_responder(tmp_path, StubTheHive(role_tagged_observables()), whitelist)

    assert output["full"]["pair_selection"] == "source-role-tags"
    assert [key for key, _ in whitelist.writes] == [PAIR_KEY]


def test_check_fails_safe_when_only_destination_tagged(tmp_path):
    write_job(tmp_path, "check")
    destination_only = [obs for obs in role_tagged_observables() if "mde:role=destination" in obs["tags"]]
    thehive = StubTheHive(destination_only + [{**OBSERVABLES[1], "tags": ["mde:role=source"]}])

    with pytest.raises(SystemExit):
        run_responder(tmp_path, thehive, StubWhitelist())

    assert read_output(tmp_path)["success"] is False
    assert thehive.closed == []
