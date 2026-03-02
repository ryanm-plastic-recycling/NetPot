from honeysentinel.util import redact_body, redact_headers, redact_telnet_password


def test_header_redaction() -> None:
    headers = {"Authorization": "Bearer abc", "Cookie": "a=b", "User-Agent": "x"}
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["User-Agent"] == "x"


def test_body_redaction_json_and_form() -> None:
    json_body = b'{"username":"u","password":"p"}'
    form_body = b"username=u&token=abc"
    out1 = redact_body("application/json", json_body)
    out2 = redact_body("application/x-www-form-urlencoded", form_body)
    assert "[REDACTED]" in out1["preview"]
    assert "[REDACTED]" in out2["preview"]


def test_telnet_password_redacted() -> None:
    assert redact_telnet_password("supersecret") == "[REDACTED]"
