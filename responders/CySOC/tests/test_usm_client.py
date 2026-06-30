import pytest
from conftest import FakeResponse

from usm_client import USMClient, USMError

CUSTOMER_REF = "https://gw.example.com/office/thehive/index.html#!/case/~4128/details"


def test_create_ticket_created_sends_expected_body(fake_http):
    fake_http.route("POST", "/api/create", FakeResponse(200, {"message": "Object successfully created"}))
    client = USMClient("https://usm", "secret", http=fake_http)

    result = client.create_ticket("DCSync attack detected", "case body", "1", CUSTOMER_REF)

    # no ticket number echoed in this response -> None (caller falls back to a readall lookup)
    assert result == ("created", None)
    call = fake_http.calls[-1]
    assert call["headers"]["apiKey"] == "secret"
    assert call["json"] == {
        "title": "DCSync attack detected",
        "desc": "case body",
        "urgencyMap1": "1",
        "impactMap1": "1",
        "type": "Disturbance",
        "customerRef": CUSTOMER_REF,
    }


def test_create_ticket_returns_ticket_no_from_response(fake_http):
    # the create response assigns the new ticket's number under newIds — returned directly, no lookup
    create_response = {
        "message": "Object successfully created",
        "object_sent": {"title": "t", "desc": "d", "customerRef": CUSTOMER_REF},
        "newIds": {"ticketno": "IN-0005727", "statusOpen": "IN_CRE"},
    }
    fake_http.route("POST", "/api/create", FakeResponse(200, create_response))
    client = USMClient("https://usm", "secret", http=fake_http)

    assert client.create_ticket("t", "d", "1", CUSTOMER_REF) == ("created", "IN-0005727")


def test_create_ticket_existing_customer_ref_returns_exists(fake_http):
    # USM returns HTTP 400 (not 2xx) for an already-used customerRef — still a benign "exists"
    fake_http.route("POST", "/api/create", FakeResponse(400, {"message": "CustomerReference exist"}))
    client = USMClient("https://usm", "secret", http=fake_http)

    assert client.create_ticket("t", "d", "3", CUSTOMER_REF) == ("exists", None)


def test_create_ticket_http_error_raises(fake_http):
    fake_http.route("POST", "/api/create", FakeResponse(500, text="boom"))
    client = USMClient("https://usm", "secret", http=fake_http)

    with pytest.raises(USMError):
        client.create_ticket("t", "d", "3", CUSTOMER_REF)


def test_create_ticket_unknown_message_raises(fake_http):
    fake_http.route("POST", "/api/create", FakeResponse(200, {"message": "something else"}))
    client = USMClient("https://usm", "secret", http=fake_http)

    with pytest.raises(USMError):
        client.create_ticket("t", "d", "3", CUSTOMER_REF)


class NonJSONResponse:
    """A 2xx response whose .json() raises, mimicking requests on an empty/non-JSON body."""

    status_code = 200
    text = ""

    def json(self):
        raise ValueError("Expecting value: line 1 column 1 (char 0)")


def test_create_ticket_non_json_body_raises_usm_error(fake_http):
    # 2xx but empty/non-JSON body must surface as a clean USMError, not a JSONDecodeError
    fake_http.route("POST", "/api/create", NonJSONResponse())
    client = USMClient("https://usm", "secret", http=fake_http)

    with pytest.raises(USMError):
        client.create_ticket("t", "d", "3", CUSTOMER_REF)


def test_find_ticket_no_returns_first_match(fake_http):
    body = {
        "message": "Objects have been loaded successfully",
        "object": {"objectArray": [{"customerRef": CUSTOMER_REF, "ticketno": "IN-0005702"}]},
    }
    fake_http.route("GET", "/api/readall", FakeResponse(200, body))
    client = USMClient("https://usm", "secret", http=fake_http)

    assert client.find_ticket_no(CUSTOMER_REF) == "IN-0005702"
    # the filter must be encoded with %20 (not '+') for spaces — the USM parser won't treat '+'
    # as a space — and the URL value percent-encoded (e.g. '#' -> %23)
    url = fake_http.calls[-1]["url"]
    assert "params" not in fake_http.calls[-1]
    assert "filter=customerRef%20eq%20%22" in url
    assert "index.html%23%21%2Fcase" in url  # '#!/case' encoded, not left as a fragment


def test_find_ticket_no_empty_array_returns_none(fake_http):
    fake_http.route("GET", "/api/readall", FakeResponse(200, {"object": {"objectArray": []}}))
    client = USMClient("https://usm", "secret", http=fake_http)

    assert client.find_ticket_no(CUSTOMER_REF) is None


def test_find_ticket_no_http_error_raises(fake_http):
    fake_http.route("GET", "/api/readall", FakeResponse(500, text="boom"))
    client = USMClient("https://usm", "secret", http=fake_http)

    with pytest.raises(USMError):
        client.find_ticket_no(CUSTOMER_REF)


def test_update_ticket_sends_desc_and_status(fake_http):
    fake_http.route(
        "PATCH", "/api/update/IN-0005702", FakeResponse(200, {"message": "Object has been successfully updated"})
    )
    client = USMClient("https://usm", "secret", http=fake_http)

    client.update_ticket("IN-0005702", "new body")

    call = fake_http.calls[-1]
    assert call["url"].endswith("/api/update/IN-0005702")
    assert call["json"] == {"desc": "new body", "statusOpen": "IN_CRE"}


def test_update_ticket_http_error_raises(fake_http):
    fake_http.route("PATCH", "/api/update/IN-0005702", FakeResponse(404, text="not found"))
    client = USMClient("https://usm", "secret", http=fake_http)

    with pytest.raises(USMError):
        client.update_ticket("IN-0005702", "new body")


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        # create response: number assigned under newIds
        ({"message": "Object successfully created", "newIds": {"ticketno": "IN-0005727"}}, "IN-0005727"),
        ({"ticketno": "IN-0005724"}, "IN-0005724"),  # flat (defensive fallback)
        ({"object": {"ticketno": "IN-0005724"}}, "IN-0005724"),  # single object
        ({"object": {"objectArray": [{"ticketno": "IN-0005724"}]}}, "IN-0005724"),  # readall array
        ({"object": {"objectArray": []}}, None),  # no match
        ({"message": "Object successfully created"}, None),  # no ticket number anywhere
        ("not a dict", None),
    ],
)
def test_extract_ticket_no_tolerates_response_shapes(payload, expected):
    assert USMClient._extract_ticket_no(payload) == expected
