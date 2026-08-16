import pytest
from conftest import FakeResponse

from thehive_client import TheHiveClient, TheHiveError

CASE_ID = "~4128"
TASK_ID = "~9001"


def query_router(**responses):
    """Dispatch /api/v1/query calls to a canned response based on the `name` query param."""

    def _route(**kwargs):
        return responses[kwargs["params"]["name"]]

    return _route


def test_close_case_false_positive_sends_two_patches_in_order(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.close_case_false_positive(CASE_ID)

    patch_calls = [c for c in fake_http.calls if c["method"] == "PATCH"]
    assert len(patch_calls) == 2
    # First PATCH closes/keeps-closed — no verdict fields yet
    assert patch_calls[0]["json"] == {"status": "Resolved"}
    # Second PATCH sets verdict without "status" so closeCase is not prepended server-side
    fp_body = patch_calls[1]["json"]
    assert "status" not in fp_body
    assert "summary" not in fp_body
    assert fp_body == {"resolutionStatus": "FalsePositive", "impactStatus": "NotApplicable"}


def test_close_case_false_positive_raises_if_first_patch_fails(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(500, text="server error"))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    with pytest.raises(TheHiveError):
        client.close_case_false_positive(CASE_ID)


def test_close_case_false_positive_raises_if_second_patch_fails(fake_http):
    call_count = {"n": 0}

    def patch_response(**kwargs):
        call_count["n"] += 1
        return FakeResponse(200, {}) if call_count["n"] == 1 else FakeResponse(500, text="server error")

    fake_http.route("PATCH", f"/api/case/{CASE_ID}", patch_response)
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    with pytest.raises(TheHiveError):
        client.close_case_false_positive(CASE_ID)


def test_close_case_true_positive_never_touches_summary(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.close_case_true_positive(CASE_ID)

    body = fake_http.calls[-1]["json"]
    assert "summary" not in body
    assert body == {"status": "Resolved", "resolutionStatus": "TruePositive", "impactStatus": "WithImpact"}


def test_close_case_indeterminate_sends_two_patches_in_order(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.close_case_indeterminate(CASE_ID)

    patch_calls = [c for c in fake_http.calls if c["method"] == "PATCH"]
    assert len(patch_calls) == 2
    assert patch_calls[0]["json"] == {"status": "Resolved"}
    body = patch_calls[1]["json"]
    assert "status" not in body
    assert body == {"resolutionStatus": "Indeterminate", "impactStatus": "NotApplicable"}


def test_close_case_indeterminate_raises_on_error(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(500, text="server error"))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    with pytest.raises(TheHiveError):
        client.close_case_indeterminate(CASE_ID)


def test_add_case_tags_merges_with_existing_tags(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.add_case_tags(CASE_ID, ["Verdict:Inconclusive"], ["MDE:EvidenceVerdict=suspicious"])

    assert fake_http.calls[-1]["json"] == {
        "tags": ["MDE:EvidenceVerdict=suspicious", "Verdict:Inconclusive"]
    }


def test_add_case_tags_is_a_noop_when_already_present(fake_http):
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.add_case_tags(CASE_ID, ["Verdict:Inconclusive"], ["Verdict:Inconclusive", "tlp:amber"])

    assert fake_http.calls == []


def test_add_case_tags_raises_on_error(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(500, text="boom"))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    with pytest.raises(TheHiveError):
        client.add_case_tags(CASE_ID, ["Verdict:Inconclusive"])


def test_create_task_completes_it_immediately(fake_http):
    fake_http.route("POST", f"/api/case/{CASE_ID}/task", FakeResponse(201, {"_id": TASK_ID}))
    fake_http.route("PATCH", f"/api/case/task/{TASK_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    task_id = client.create_task(CASE_ID, "Log", "CySOC")

    assert task_id == TASK_ID
    patch_calls = [c for c in fake_http.calls if c["method"] == "PATCH"]
    assert [c["json"]["status"] for c in patch_calls] == ["InProgress", "Completed"]


def test_get_or_create_task_returns_existing_completed_task_without_patching(fake_http):
    fake_http.route(
        "POST",
        "/api/v1/query",
        FakeResponse(200, [{"_id": TASK_ID, "group": "CySOC", "title": "Log", "status": "Completed"}]),
    )
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    task_id = client.get_or_create_task(CASE_ID, "CySOC", "Log")

    assert task_id == TASK_ID
    assert not any(c["method"] == "PATCH" for c in fake_http.calls)


def test_get_or_create_task_closes_existing_task_left_open(fake_http):
    fake_http.route(
        "POST",
        "/api/v1/query",
        FakeResponse(200, [{"_id": TASK_ID, "group": "CySOC", "title": "Log", "status": "Waiting"}]),
    )
    fake_http.route("PATCH", f"/api/case/task/{TASK_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    task_id = client.get_or_create_task(CASE_ID, "CySOC", "Log")

    assert task_id == TASK_ID
    patch_calls = [c for c in fake_http.calls if c["method"] == "PATCH"]
    assert [c["json"]["status"] for c in patch_calls] == ["InProgress", "Completed"]


def test_get_or_create_task_creates_when_missing(fake_http):
    fake_http.route("POST", "/api/v1/query", FakeResponse(200, []))
    fake_http.route("POST", f"/api/case/{CASE_ID}/task", FakeResponse(201, {"_id": TASK_ID}))
    fake_http.route("PATCH", f"/api/case/task/{TASK_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    task_id = client.get_or_create_task(CASE_ID, "CySOC", "Log")

    assert task_id == TASK_ID


def test_add_task_log_posts_message(fake_http):
    fake_http.route("POST", f"/api/case/task/{TASK_ID}/log", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.add_task_log(TASK_ID, "hello")

    call = fake_http.calls[-1]
    assert call["json"] == {"message": "hello"}


def test_add_task_log_raises_on_error(fake_http):
    fake_http.route("POST", f"/api/case/task/{TASK_ID}/log", FakeResponse(500, text="boom"))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    with pytest.raises(TheHiveError):
        client.add_task_log(TASK_ID, "hello")


def test_get_last_task_log_message_returns_most_recent(fake_http):
    fake_http.route("POST", "/api/v1/query", FakeResponse(200, [{"message": "latest"}, {"message": "older"}]))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    assert client.get_last_task_log_message(TASK_ID) == "latest"


def test_get_last_task_log_message_returns_none_when_no_logs(fake_http):
    fake_http.route("POST", "/api/v1/query", FakeResponse(200, []))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    assert client.get_last_task_log_message(TASK_ID) is None


def test_log_to_task_finds_task_then_logs(fake_http):
    fake_http.route(
        "POST",
        "/api/v1/query",
        query_router(
            **{
                "case-tasks": FakeResponse(200, [{"_id": TASK_ID, "group": "CySOC", "title": "Log", "status": "Completed"}]),
                "task-logs": FakeResponse(200, []),
            }
        ),
    )
    fake_http.route("POST", f"/api/case/task/{TASK_ID}/log", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.log_to_task(CASE_ID, "CySOC", "Log", "hello")

    log_calls = [c for c in fake_http.calls if c["url"].endswith(f"{TASK_ID}/log")]
    assert log_calls[0]["json"] == {"message": "hello"}


def test_log_to_task_skips_exact_duplicate_of_last_message(fake_http):
    fake_http.route(
        "POST",
        "/api/v1/query",
        query_router(
            **{
                "case-tasks": FakeResponse(200, [{"_id": TASK_ID, "group": "CySOC", "title": "Log", "status": "Completed"}]),
                "task-logs": FakeResponse(200, [{"message": "hello"}]),
            }
        ),
    )
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.log_to_task(CASE_ID, "CySOC", "Log", "hello")

    assert not any(c["url"].endswith(f"{TASK_ID}/log") for c in fake_http.calls)


def test_log_to_task_skips_dedup_check_when_dedup_false(fake_http):
    fake_http.route(
        "POST",
        "/api/v1/query",
        query_router(
            **{
                "case-tasks": FakeResponse(200, [{"_id": TASK_ID, "group": "CySOC", "title": "Log", "status": "Completed"}]),
            }
        ),
    )
    fake_http.route("POST", f"/api/case/task/{TASK_ID}/log", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.log_to_task(CASE_ID, "CySOC", "Log", "repeated message", dedup=False)

    log_calls = [c for c in fake_http.calls if c["url"].endswith(f"{TASK_ID}/log")]
    assert len(log_calls) == 1
    assert log_calls[0]["json"] == {"message": "repeated message"}
    # No query for task-logs was made — dedup check was skipped entirely
    query_calls = [c for c in fake_http.calls if "/api/v1/query" in c["url"]]
    assert not any(c.get("params", {}).get("name") == "task-logs" for query_calls in [query_calls] for c in query_calls)


def test_log_to_task_writes_when_different_from_last(fake_http):
    fake_http.route(
        "POST",
        "/api/v1/query",
        query_router(
            **{
                "case-tasks": FakeResponse(200, [{"_id": TASK_ID, "group": "CySOC", "title": "Log", "status": "Completed"}]),
                "task-logs": FakeResponse(200, [{"message": "previous message"}]),
            }
        ),
    )
    fake_http.route("POST", f"/api/case/task/{TASK_ID}/log", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.log_to_task(CASE_ID, "CySOC", "Log", "new message")

    log_calls = [c for c in fake_http.calls if c["url"].endswith(f"{TASK_ID}/log")]
    assert log_calls[0]["json"] == {"message": "new message"}
