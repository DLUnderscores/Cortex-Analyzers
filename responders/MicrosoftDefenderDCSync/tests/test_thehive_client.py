import pytest
from conftest import FakeResponse

from thehive_client import TheHiveClient, TheHiveError

CASE_ID = "~4128"
TASK_ID = "~9001"


def test_close_case_false_positive_never_touches_summary(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.close_case_false_positive(CASE_ID)

    body = fake_http.calls[-1]["json"]
    assert "summary" not in body
    assert body == {"status": "Resolved", "resolutionStatus": "FalsePositive", "impactStatus": "NotApplicable"}


def test_close_case_true_positive_never_touches_summary(fake_http):
    fake_http.route("PATCH", f"/api/case/{CASE_ID}", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.close_case_true_positive(CASE_ID)

    body = fake_http.calls[-1]["json"]
    assert "summary" not in body
    assert body == {"status": "Resolved", "resolutionStatus": "TruePositive", "impactStatus": "WithImpact"}


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


def test_log_to_task_finds_task_then_logs(fake_http):
    fake_http.route(
        "POST",
        "/api/v1/query",
        FakeResponse(200, [{"_id": TASK_ID, "group": "CySOC", "title": "Log", "status": "Completed"}]),
    )
    fake_http.route("POST", f"/api/case/task/{TASK_ID}/log", FakeResponse(200, {}))
    client = TheHiveClient("http://thehive", "key", http=fake_http)

    client.log_to_task(CASE_ID, "CySOC", "Log", "hello")

    log_calls = [c for c in fake_http.calls if c["url"].endswith(f"{TASK_ID}/log")]
    assert log_calls[0]["json"] == {"message": "hello"}
