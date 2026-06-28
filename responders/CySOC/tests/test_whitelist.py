import base64

import pytest
import yaml
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


def user_obs(data="svc-sync", user_id=USER_GUID, predicate="Account_Object_ID", tags=(), extra=None):
    taxonomies = [{"predicate": predicate, "value": user_id}]
    for extra_predicate, extra_value in (extra or {}).items():
        taxonomies.append({"predicate": extra_predicate, "value": extra_value})
    reports = {"MicrosoftDefender_GetUserInfo_1_0": {"taxonomies": taxonomies}}
    return observable("username", data, tags=tags, reports=reports)


def ip_host_obs(data="10.0.0.5", device_id=DEVICE_ID, tags=()):
    reports = {"MicrosoftDefender_GetDeviceInfo_1_0": {"taxonomies": [{"predicate": "Device_ID", "value": device_id}]}}
    return observable("ip", data, tags=tags, reports=reports)


def fqdn_host_obs(data="ws01.socdev.lan", device_id=DEVICE_ID, tags=()):
    reports = {"MicrosoftDefender_GetDeviceInfo_1_0": {"taxonomies": [{"predicate": "Device_ID", "value": device_id}]}}
    return observable("fqdn", data, tags=tags, reports=reports)


def mail_user_obs(data="svc-sync@socdev.lan", user_id=USER_GUID, tags=()):
    reports = {"MicrosoftDefender_GetUserInfo_1_0": {"taxonomies": [{"predicate": "Account_Object_ID", "value": user_id}]}}
    return observable("mail", data, tags=tags, reports=reports)


def not_found_obs(data_type, data, analyzer="MicrosoftDefender_GetDeviceInfo_1_0", tags=()):
    # MDE looked the observable up but it is absent — the Not_Found taxonomy carries a null value.
    reports = {analyzer: {"taxonomies": [{"namespace": "MDE", "predicate": "Not_Found", "value": None}]}}
    return observable(data_type, data, tags=tags, reports=reports)


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


def test_resolve_user_display_prefers_upn_over_raw_observable_data():
    # observable spelled as the Entra object-id GUID, but the report carries a UPN → label is the UPN
    user = user_obs(data=USER_GUID, extra={"UPN": "dcsync@contoso.onmicrosoft.com", "Display_Name": "DC Sync"})
    pairs, _, _ = PairResolver().resolve([host_obs(), user])
    assert pairs[0]["user"] == "dcsync@contoso.onmicrosoft.com"
    assert pairs[0]["key"] == pair_key(USER_GUID, DEVICE_ID)  # matching still keyed on the object id


def test_resolve_user_display_falls_back_to_display_name_then_data():
    by_display_name = user_obs(data=USER_GUID, extra={"Display_Name": "DC Sync"})
    pairs, _, _ = PairResolver().resolve([host_obs(), by_display_name])
    assert pairs[0]["user"] == "DC Sync"
    # no UPN/Display_Name in the report → keep the observable's own text
    pairs2, _, _ = PairResolver().resolve([host_obs(), user_obs(data="svc-sync")])
    assert pairs2[0]["user"] == "svc-sync"


def test_resolve_records_user_id_predicate_for_entra_id():
    pairs, _, _ = PairResolver().resolve([host_obs(), user_obs()])
    assert pairs[0]["user_id_predicate"] == "Account_Object_ID"


def test_resolve_records_user_id_predicate_for_onprem_only_id():
    pairs, _, _ = PairResolver().resolve([host_obs(), user_obs(predicate="OnPrem_Object_ID")])
    assert pairs[0]["user_id_predicate"] == "OnPrem_Object_ID"


def test_resolve_carries_supplementary_user_ids():
    user = user_obs(
        extra={"OnPrem_Object_ID": "onprem-guid", "Identity_Account_ID": "identity-account-guid"}
    )
    pairs, _, _ = PairResolver().resolve([host_obs(), user])
    assert pairs[0]["entra_object_id"] == USER_GUID
    assert pairs[0]["onprem_object_id"] == "onprem-guid"
    assert pairs[0]["identity_account_id"] == "identity-account-guid"


def test_resolve_supplementary_ids_default_to_none_when_absent():
    pairs, _, _ = PairResolver().resolve([host_obs(), user_obs()])
    assert pairs[0]["entra_object_id"] == USER_GUID
    assert pairs[0]["onprem_object_id"] is None
    assert pairs[0]["identity_account_id"] is None


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


def test_resolve_ip_observable_to_device():
    pairs, unresolved, _ = PairResolver().resolve([ip_host_obs(), user_obs()])
    assert unresolved == []
    assert len(pairs) == 1
    assert pairs[0]["host"] == "10.0.0.5"
    assert pairs[0]["device_id"] == DEVICE_ID


def test_resolve_mail_observable_to_user():
    pairs, unresolved, _ = PairResolver().resolve([host_obs(), mail_user_obs()])
    assert unresolved == []
    assert len(pairs) == 1
    assert pairs[0]["user"] == "svc-sync@socdev.lan"
    assert pairs[0]["user_id"] == USER_GUID


def test_resolve_ignores_not_found_observable():
    # a host MDE looked up but couldn't find is skipped, not unresolved, and doesn't block the job
    observables = [host_obs(), not_found_obs("ip", "10.9.9.9"), user_obs()]
    pairs, unresolved, _ = PairResolver().resolve(observables)
    assert unresolved == []
    assert len(pairs) == 1
    assert pairs[0]["host"] == "ws01.socdev.lan"


def test_resolve_not_found_only_host_yields_no_pairs():
    pairs, unresolved, _ = PairResolver().resolve([not_found_obs("hostname", "ghost"), user_obs()])
    assert unresolved == []
    assert pairs == []


def test_resolve_untagged_treated_as_source_alongside_source_tag():
    observables = [
        host_obs("ws01", DEVICE_ID, tags=["MDE:Role=source"]),
        host_obs("ws02", "f" * 40),  # untagged → source, kept (not dropped)
        user_obs(tags=["MDE:Role=source"]),
    ]
    pairs, unresolved, selection = PairResolver().resolve(observables)
    assert unresolved == []
    assert selection == "source-role-tags"
    assert {p["host"] for p in pairs} == {"ws01", "ws02"}


def test_resolve_destination_excludes_same_device_untagged_ip():
    # the DC is tagged destination only on its hostname; its untagged same-device ip is excluded too
    observables = [
        host_obs("dc01", DEVICE_ID, tags=["MDE:Role=destination"]),
        ip_host_obs("10.0.0.1", DEVICE_ID),
        user_obs(tags=["MDE:Role=source"]),
    ]
    pairs, unresolved, _ = PairResolver().resolve(observables)
    assert unresolved == []
    assert pairs == []


def test_resolve_deduplicates_hostname_and_ip_same_device():
    observables = [host_obs("ws01.socdev.lan", DEVICE_ID), ip_host_obs("10.0.0.5", DEVICE_ID), user_obs()]
    pairs, unresolved, _ = PairResolver().resolve(observables)
    assert unresolved == []
    assert len(pairs) == 1


def test_resolve_pairs_from_fqdn_host():
    # a host present only as an fqdn resolves to a device (via its Device_ID) and pairs with a user
    pairs, unresolved, _ = PairResolver().resolve([fqdn_host_obs("ws01.socdev.lan", DEVICE_ID), user_obs()])
    assert unresolved == []
    assert len(pairs) == 1
    assert pairs[0]["device_id"] == DEVICE_ID
    assert pairs[0]["host"] == "ws01.socdev.lan"


def test_resolve_deduplicates_hostname_and_fqdn_same_device():
    # same machine seen as hostname + fqdn collapses to one device (canonical Device_ID)
    observables = [host_obs("ws01", DEVICE_ID), fqdn_host_obs("ws01.socdev.lan", DEVICE_ID), user_obs()]
    pairs, unresolved, _ = PairResolver().resolve(observables)
    assert unresolved == []
    assert len(pairs) == 1


def test_resolve_destination_fqdn_excludes_same_device():
    # a DC tagged destination on its fqdn excludes its untagged same-device hostname too
    observables = [
        fqdn_host_obs("dc01.socdev.lan", DEVICE_ID, tags=["MDE:Role=destination"]),
        host_obs("dc01", DEVICE_ID),
        user_obs(tags=["MDE:Role=source"]),
    ]
    pairs, unresolved, _ = PairResolver().resolve(observables)
    assert unresolved == []
    assert pairs == []


def consul_item(key, entries, modify_index=1):
    body = yaml.safe_dump(entries, default_flow_style=False, sort_keys=True, indent=2)
    return [{"Key": key, "Value": base64.b64encode(body.encode()).decode(), "ModifyIndex": modify_index}]


def test_consul_whitelist_entries(fake_http):
    key = "cysoc/office/sirp/dcsync/whitelist"
    pkey = pair_key(USER_GUID, DEVICE_ID)
    fake_http.route("GET", f"/v1/kv/{key}", FakeResponse(200, consul_item(key, {pkey: {"account": "svc-sync"}})))
    wl = ConsulWhitelist("http://consul:8500", key, http=fake_http)
    assert wl.entries() == {pkey: {"account": "svc-sync"}}


def test_consul_whitelist_empty_on_404(fake_http):
    fake_http.route("GET", "/v1/kv/", FakeResponse(404))
    wl = ConsulWhitelist("http://consul:8500", "some/key", http=fake_http)
    assert wl.entries() == {}


def test_consul_whitelist_put_and_token_header(fake_http):
    key = "cysoc/office/sirp/dcsync/whitelist"
    pkey = pair_key(USER_GUID, DEVICE_ID)
    fake_http.route("GET", f"/v1/kv/{key}", FakeResponse(200, consul_item(key, {}, modify_index=5)))
    fake_http.route("PUT", f"/v1/kv/{key}", FakeResponse(200, True))
    wl = ConsulWhitelist("http://consul:8500/", key, token="s3cret", http=fake_http)
    wl.put(pkey, {"account": "svc-sync"})
    call = fake_http.calls[-1]
    assert call["headers"] == {"X-Consul-Token": "s3cret"}
    assert call["params"] == {"cas": 5}
    assert yaml.safe_load(call["data"]) == {pkey: {"account": "svc-sync"}}


def test_consul_whitelist_put_creates_when_absent(fake_http):
    key = "cysoc/office/sirp/dcsync/whitelist"
    pkey = pair_key(USER_GUID, DEVICE_ID)
    fake_http.route("GET", f"/v1/kv/{key}", FakeResponse(404))
    fake_http.route("PUT", f"/v1/kv/{key}", FakeResponse(200, True))
    wl = ConsulWhitelist("http://consul:8500", key, http=fake_http)
    wl.put(pkey, {"account": "svc-sync"})
    call = fake_http.calls[-1]
    assert call["params"] == {"cas": 0}
    assert yaml.safe_load(call["data"]) == {pkey: {"account": "svc-sync"}}


def test_consul_whitelist_put_retries_on_cas_conflict(fake_http):
    key = "cysoc/office/sirp/dcsync/whitelist"
    pkey = pair_key(USER_GUID, DEVICE_ID)
    fake_http.route("GET", f"/v1/kv/{key}", FakeResponse(200, consul_item(key, {}, modify_index=5)))
    put_attempts = {"count": 0}

    def put_response(**kwargs):
        put_attempts["count"] += 1
        return FakeResponse(200, put_attempts["count"] > 1)

    fake_http.route("PUT", f"/v1/kv/{key}", put_response)
    wl = ConsulWhitelist("http://consul:8500", key, http=fake_http)
    wl.put(pkey, {"account": "svc-sync"})
    assert put_attempts["count"] == 2


def test_consul_whitelist_put_raises_after_max_cas_attempts(fake_http):
    key = "cysoc/office/sirp/dcsync/whitelist"
    pkey = pair_key(USER_GUID, DEVICE_ID)
    fake_http.route("GET", f"/v1/kv/{key}", FakeResponse(200, consul_item(key, {}, modify_index=5)))
    fake_http.route("PUT", f"/v1/kv/{key}", FakeResponse(200, False))
    wl = ConsulWhitelist("http://consul:8500", key, http=fake_http)
    with pytest.raises(ConsulKVError):
        wl.put(pkey, {"account": "svc-sync"})


def test_consul_whitelist_raises_on_error(fake_http):
    fake_http.route("GET", "/v1/kv/", FakeResponse(500, text="boom"))
    wl = ConsulWhitelist("http://consul:8500", "some/key", http=fake_http)
    with pytest.raises(ConsulKVError):
        wl.entries()
