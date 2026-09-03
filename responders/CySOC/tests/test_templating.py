import templating


def test_render_substitutes_known_names():
    assert templating.render("[[ title ]] / [[title]]", {"title": "Case A"}) == "Case A / Case A"


def test_render_walks_dotted_names_into_nested_context():
    context = {"cf": {"internal-ref": "office:defender-123"}}
    assert templating.render("ref=[[ cf.internal-ref ]]", context) == "ref=office:defender-123"


def test_render_stringifies_non_string_values():
    assert templating.render("sev=[[ severity ]]", {"severity": 4}) == "sev=4"


def test_render_treats_a_present_but_null_value_as_empty_without_reporting_it():
    # A case with no description is normal, not a template error.
    unknown = set()
    assert templating.render("[[ description ]]!", {"description": None}, unknown) == "!"
    assert unknown == set()


def test_render_reports_unknown_names_and_renders_them_empty():
    unknown = set()
    assert templating.render("a[[ nope ]]b[[ cf.missing ]]c", {"cf": {}}, unknown) == "abc"
    assert unknown == {"nope", "cf.missing"}


def test_render_leaves_consul_template_style_braces_alone():
    # case-reasoning.yml is rendered by consul-template with the default {{ }} delimiters, so
    # templates use [[ ]]; anything in {{ }} is not ours to touch.
    assert templating.render("{{ key \"x\" }} [[ t ]]", {"t": "v"}) == '{{ key "x" }} v'


def test_render_payload_renders_strings_and_passes_other_types_through():
    template = {"title": "[[ title ]]", "flag": True, "count": 3, "drop": None}
    payload, unknown = templating.render_payload(template, {"title": "T"})

    assert payload == {"title": "T", "flag": True, "count": 3, "drop": None}
    assert unknown == []


def test_render_payload_collects_unknown_names_sorted():
    payload, unknown = templating.render_payload({"desc": "[[ b ]][[ a ]]"}, {})

    assert payload == {"desc": ""}
    assert unknown == ["a", "b"]


def test_render_payload_of_a_non_mapping_is_empty():
    assert templating.render_payload("not a mapping", {}) == ({}, [])
