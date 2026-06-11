import base64
import json

import pytest
from conftest import FakeResponse

from whitelist import (
    ConsulKVError,
    ConsulWhitelist,
    PairResolver,
    pair_key,
    select_candidates,
    taxonomy_value,
)

USER_GUID = "11111111-2222-3333-4444-555555555555"
DEVICE_ID = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def observable(data_type, data, tags=(), reports=None):
    return {"dataType": data_type, "data": data, "tags": list(tags), "reports": reports or {}}


def host_obs(data="ws01.socdev.lan", device_id=DEVICE_ID, tags=()):
    reports = {"MicrosoftDefender_GetDeviceInfo_1_0": {"taxonomies": [{"predicate": "Device_ID", "value": device_id}]}}
    return observable("hostname", data, tags=tags, reports=reports)


def user_obs(data="svc-sync", user_id=USER_GUID, predicate="Account_Object_ID", tags=()):
    reports = {"MicrosoftDefender_GetUserInfo_1_0": {"taxonomies": [{"predicate": predicate, "value": user_id}]}}
    return observable("username", data, tags=tags, reports=reports)


def test_pair_key_normalizes_case_and_whitespace():
    assert pair_key(f" {USER_GUID.upper()} ", DEVICE_ID.upper()) == f"{USER_GUID}:{DEVICE_ID}"


def test_select_candidates_filters_types_and_analyzer_artifacts():
    observables = [
        host_obs(),
        observable("fqdn", "dc01.socdev.lan", tags=["MicrosoftDefender", "user=svc-sync"]),
        observable("ip", "10.0.0.5"),
        user_obs(),
    ]
    selected = select_candidates(observables, ("hostname", "fqdn"))
    assert [o["data"] for o in selected] == ["ws01.socdev.lan"]


def test_taxonomy_value_honors_predicate_priority():
    obs = observable(
        "username",
        "svc-sync",
        reports={
            "MicrosoftDefender_GetUserInfo_1_0": {
                "taxonomies": [
                    {"predicate": "OnPrem_Object_ID", "value": "onprem-guid"},
                    {"predicate": "Account_Object_ID", "value": USER_GUID},
                ]
            }
        },
    )
    assert taxonomy_value(obs, ("Account_Object_ID", "OnPrem_Object_ID")) == USER_GUID
    assert taxonomy_value(obs, ("OnPrem_Object_ID",)) == "onprem-guid"
    assert taxonomy_value(observable("username", "x"), ("Account_Object_ID",)) is None


def test_resolve_pairs_from_reports():
    pairs, unresolved, selection = PairResolver().resolve([host_obs(), user_obs()])
    assert unresolved == []
    assert selection == "all-candidates"
    assert len(pairs) == 1
    assert pairs[0]["key"] == pair_key(USER_GUID, DEVICE_ID)
    assert pairs[0]["user"] == "svc-sync"
    assert pairs[0]["host"] == "ws01.socdev.lan"


def test_resolve_reports_observables_without_enrichment_as_unresolved():
    pairs, unresolved, _ = PairResolver().resolve([observable("hostname", "ghost"), user_obs()])
    assert pairs == []
    assert len(unresolved) == 1
    assert unresolved[0]["data"] == "ghost"
    assert "enrichment" in unresolved[0]["reason"]


def test_resolve_deduplicates_same_canonical_identity():
    # short hostname and FQDN of the same machine resolve to one host entry
    observables = [host_obs("ws01"), host_obs("ws01.socdev.lan"), user_obs()]
    pairs, unresolved, _ = PairResolver().resolve(observables)
    assert unresolved == []
    assert len(pairs) == 1


def test_resolve_builds_all_pair_combinations():
    observables = [
        host_obs("ws01", DEVICE_ID),
        host_obs("ws02", "f" * 40),
        user_obs(),
    ]
    pairs, _, selection = PairResolver().resolve(observables)
    assert selection == "all-candidates"
    assert {p["key"] for p in pairs} == {pair_key(USER_GUID, DEVICE_ID), pair_key(USER_GUID, "f" * 40)}


def test_resolve_prefers_source_role_tagged_candidates():
    observables = [
        host_obs("ws01", DEVICE_ID, tags=["mde:role=source"]),
        host_obs("dc01", "f" * 40, tags=["mde:role=destination"]),
        user_obs(tags=["mde:role=source"]),
    ]
    pairs, unresolved, selection = PairResolver().resolve(observables)
    assert unresolved == []
    assert selection == "source-role-tags"
    assert len(pairs) == 1
    assert pairs[0]["key"] == pair_key(USER_GUID, DEVICE_ID)
    assert pairs[0]["host"] == "ws01"


def test_resolve_excluded_destination_does_not_require_enrichment():
    # the destination DC has no enrichment report but is filtered out by role, so it must not block
    observables = [
        host_obs("ws01", DEVICE_ID, tags=["mde:role=source"]),
        observable("hostname", "dc01", tags=["mde:role=destination"]),
        user_obs(tags=["mde:role=source"]),
    ]
    pairs, unresolved, _ = PairResolver().resolve(observables)
    assert unresolved == []
    assert len(pairs) == 1


def test_resolve_only_destination_tagged_yields_no_pairs():
    observables = [
        host_obs("dc01", "f" * 40, tags=["mde:role=destination"]),
        user_obs(tags=["mde:role=source"]),
    ]
    pairs, unresolved, selection = PairResolver().resolve(observables)
    assert pairs == []
    assert unresolved == []
    assert selection == "source-role-tags"


def consul_item(prefix, key, metadata):
    return {"Key": f"{prefix}/{key}", "Value": base64.b64encode(json.dumps(metadata).encode()).decode()}


def test_consul_whitelist_entries(fake_http):
    prefix = "cysoc/office/sirp/dcsync/whitelist"
    key = pair_key(USER_GUID, DEVICE_ID)
    fake_http.route("GET", f"/v1/kv/{prefix}", FakeResponse(200, [consul_item(prefix, key, {"account": "svc-sync"})]))
    wl = ConsulWhitelist("http://consul:8500", prefix, http=fake_http)
    assert wl.entries() == {key: {"account": "svc-sync"}}


def test_consul_whitelist_empty_on_404(fake_http):
    fake_http.route("GET", "/v1/kv/", FakeResponse(404))
    wl = ConsulWhitelist("http://consul:8500", "some/prefix", http=fake_http)
    assert wl.entries() == {}


def test_consul_whitelist_put_and_token_header(fake_http):
    prefix = "cysoc/office/sirp/dcsync/whitelist"
    key = pair_key(USER_GUID, DEVICE_ID)
    fake_http.route("PUT", f"/v1/kv/{prefix}/{key}", FakeResponse(200, True))
    wl = ConsulWhitelist("http://consul:8500/", prefix, token="s3cret", http=fake_http)
    wl.put(key, {"account": "svc-sync"})
    call = fake_http.calls[-1]
    assert call["headers"] == {"X-Consul-Token": "s3cret"}
    assert json.loads(call["data"]) == {"account": "svc-sync"}


def test_consul_whitelist_raises_on_error(fake_http):
    fake_http.route("GET", "/v1/kv/", FakeResponse(500, text="boom"))
    wl = ConsulWhitelist("http://consul:8500", "some/prefix", http=fake_http)
    with pytest.raises(ConsulKVError):
        wl.entries()
