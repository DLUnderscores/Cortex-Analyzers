import base64

import pytest
import yaml
from conftest import FakeResponse

import case_reasoning as cr

MAPPINGS = {
    "_default_": {
        "DCSync Attack (Microsoft Defender for Identity)": ["dcsync attack"],
        "IRM#2 Windows Intrusion": ["hands-on-keyboard attack"],
        "IRM#7 Windows Malware Detection": ["malware", "malicious file"],
    },
    "office": {"IRM#7 Windows Malware Detection": ["office malware"]},
}

REASONING = {
    "_default_": {
        "IRM#7 Windows Malware Detection": {
            "response": {
                "CySOC_Malware_Respond_1_0": {
                    "type": "__case__",
                    "value": "Success",
                    "usm_template": {"title": "default [[ title ]]"},
                }
            }
        },
        "IRM#2 Windows Intrusion": {
            "response": {"CySOC_Malware_Respond_1_0": {"type": "__case__", "value": "Success"}}
        },
    },
    "office": {
        "IRM#7 Windows Malware Detection": {
            "response": {
                "CySOC_Malware_Respond_1_0": {
                    "type": "__case__",
                    "usm_template": {"title": "office [[ title ]]"},
                }
            }
        }
    },
}


def kv_response(document):
    encoded = base64.b64encode(yaml.safe_dump(document).encode()).decode()
    return FakeResponse(200, [{"Value": encoded, "ModifyIndex": 7}])


# --- read_kv_yaml ---------------------------------------------------------------


def test_read_kv_yaml_decodes_the_document(fake_http):
    fake_http.route("GET", "/v1/kv/cysoc/office/case-reasoning", kv_response(REASONING))

    assert cr.read_kv_yaml("http://consul:8500", "cysoc/office/case-reasoning", http=fake_http) == REASONING


def test_read_kv_yaml_returns_none_for_a_missing_key(fake_http):
    fake_http.route("GET", "/v1/kv/", FakeResponse(404, None))

    assert cr.read_kv_yaml("http://consul:8500", "nope", http=fake_http) is None


def test_read_kv_yaml_raises_on_http_error(fake_http):
    fake_http.route("GET", "/v1/kv/", FakeResponse(500, None, text="boom"))

    with pytest.raises(cr.CaseReasoningError):
        cr.read_kv_yaml("http://consul:8500", "k", http=fake_http)


def test_read_kv_yaml_raises_on_malformed_yaml(fake_http):
    broken = base64.b64encode(b"a:\n  - b\n c").decode()
    fake_http.route("GET", "/v1/kv/", FakeResponse(200, [{"Value": broken}]))

    with pytest.raises(cr.CaseReasoningError):
        cr.read_kv_yaml("http://consul:8500", "k", http=fake_http)


def test_read_kv_yaml_sends_the_acl_token_when_given(fake_http):
    fake_http.route("GET", "/v1/kv/", kv_response({}))

    cr.read_kv_yaml("http://consul:8500", "k", token="t0ken", http=fake_http)  # noqa: S106

    assert fake_http.calls[-1]["headers"]["X-Consul-Token"] == "t0ken"


# --- org resolution (must stay in step with the SOAR's AlertsHelper) -------------


def test_select_org_config_prefers_a_named_org_block():
    assert cr.select_org_config(MAPPINGS, "office") == MAPPINGS["office"]


def test_select_org_config_falls_back_to_default_for_an_unknown_org():
    assert cr.select_org_config(MAPPINGS, "nowhere") == MAPPINGS["_default_"]
    assert cr.select_org_config(MAPPINGS, None) == MAPPINGS["_default_"]


def test_select_org_config_returns_a_flat_legacy_document_unchanged():
    flat = {"IRM#7 Windows Malware Detection": {}}
    assert cr.select_org_config(flat, "office") == flat


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ({"customFields": {"internal-ref": {"string": "office:defender-1"}}}, "office"),
        ({"customFields": [{"name": "internal-ref", "value": "office:defender-1"}]}, "office"),
        ({"customFields": {"internal-ref": {"string": "defender-1"}}}, None),  # bare ref, no org
        ({"customFields": {}}, None),
        ({}, None),
    ],
)
def test_org_of_falls_back_to_the_scoped_internal_ref(case, expected):
    """With no organisation parameter (a run straight from the Cortex UI), the ref carries it."""
    assert cr.org_of(case) == expected


def test_org_of_prefers_the_job_organisation():
    """The case's owning organisation, which TheHive passes in, decides the config block."""
    case = {"customFields": {"internal-ref": {"string": "office:defender-1"}}}
    assert cr.org_of(case, "acme") == "acme"


def test_org_of_uses_the_job_organisation_for_a_bare_ref():
    case = {"customFields": {"internal-ref": {"string": "defender-1"}}}
    assert cr.org_of(case, "acme") == "acme"


# --- title -> case template ------------------------------------------------------


def test_resolve_template_name_matches_a_needle_case_insensitively():
    name = cr.resolve_template_name("Malicious File detected", MAPPINGS["_default_"])
    assert name == "IRM#7 Windows Malware Detection"


def test_resolve_template_name_strips_thehives_duplicate_counter():
    name = cr.resolve_template_name("DCSync attack (3)", MAPPINGS["_default_"])
    assert name == "DCSync Attack (Microsoft Defender for Identity)"


def test_resolve_template_name_returns_none_when_nothing_matches():
    assert cr.resolve_template_name("Unrelated alert", MAPPINGS["_default_"]) is None


# --- end-to-end template lookup --------------------------------------------------


def test_find_usm_template_uses_the_default_block():
    template, name = cr.find_usm_template(
        REASONING, MAPPINGS, None, "Malware detected on workstation", "CySOC_Malware_Respond"
    )
    assert name == "IRM#7 Windows Malware Detection"
    assert template == {"title": "default [[ title ]]"}


def test_find_usm_template_prefers_the_organisations_own_block():
    template, name = cr.find_usm_template(
        REASONING, MAPPINGS, "office", "Office malware seen", "CySOC_Malware_Respond"
    )
    assert name == "IRM#7 Windows Malware Detection"
    assert template == {"title": "office [[ title ]]"}


def test_find_usm_template_is_per_case_type():
    # IRM#2 has a response entry but no usm_template — the built-in layout applies there.
    template, name = cr.find_usm_template(
        REASONING, MAPPINGS, None, "Hands-on-keyboard attack", "CySOC_Malware_Respond"
    )
    assert name == "IRM#2 Windows Intrusion"
    assert template is None


def test_find_usm_template_matches_a_versioned_responder_name_by_prefix():
    reasoning = {
        "_default_": {
            "IRM#7 Windows Malware Detection": {
                "response": {"CySOC_Malware_Respond_1_1": {"usm_template": {"desc": "v11"}}}
            }
        }
    }
    template, _ = cr.find_usm_template(reasoning, MAPPINGS, None, "malware", "CySOC_Malware_Respond")
    assert template == {"desc": "v11"}


def test_find_usm_template_ignores_another_responders_entry():
    reasoning = {
        "_default_": {
            "IRM#7 Windows Malware Detection": {
                "response": {"CySOC_DCSync_Respond_1_0": {"usm_template": {"desc": "wrong"}}}
            }
        }
    }
    template, _ = cr.find_usm_template(reasoning, MAPPINGS, None, "malware", "CySOC_Malware_Respond")
    assert template is None


def test_find_usm_template_returns_nothing_when_the_title_matches_no_template():
    assert cr.find_usm_template(REASONING, MAPPINGS, None, "Unrelated", "CySOC_Malware_Respond") == (None, None)


def test_find_usm_template_tolerates_missing_documents():
    assert cr.find_usm_template(None, None, None, "malware", "CySOC_Malware_Respond") == (None, None)
