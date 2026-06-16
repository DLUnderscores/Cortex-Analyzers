import json

import pytest

from dcsync_whitelist import DCSyncWhitelistResponder
from whitelist import pair_key

USER_GUID = "11111111-2222-3333-4444-555555555555"
DEVICE_ID = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
PAIR_KEY = pair_key(USER_GUID, DEVICE_ID)

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

    def log_to_task(self, case_id, group, title, message):
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


class ResponderUnderTest(DCSyncWhitelistResponder):
    def __init__(self, job_directory, thehive, whitelist):
        self.stub_thehive = thehive
        self.stub_whitelist = whitelist
        super().__init__(job_directory=str(job_directory))

    def _thehive(self):
        return self.stub_thehive

    def _whitelist(self):
        return self.stub_whitelist


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


def run_responder(tmp_path, thehive, whitelist):
    responder = ResponderUnderTest(tmp_path, thehive, whitelist)
    responder.run()
    return read_output(tmp_path)


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
