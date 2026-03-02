from honeysentinel.config import RulesConfig
from honeysentinel.events import Event
from honeysentinel.rules import RuleEngine


def _event(src_ip: str, dst_port: int, listener: str = "tcp", message: str = "", data: dict | None = None) -> Event:
    return Event(
        event_type="test",
        src_ip=src_ip,
        src_port=4567,
        dst_port=dst_port,
        listener=listener,
        session_id="s",
        message=message,
        data=data or {},
    )


def test_portscan_and_suppression() -> None:
    engine = RuleEngine(RulesConfig(portscan_distinct_ports=3, suppression_seconds=9999))
    alerts = []
    for p in [1, 2, 3]:
        alerts.extend(engine.evaluate(_event("1.1.1.1", 1000 + p)))
    assert any(a.rule == "portscan" for a in alerts)
    suppressed = engine.evaluate(_event("1.1.1.1", 2000))
    assert all(a.rule != "portscan" for a in suppressed)


def test_burst_http_path_and_payload_keyword() -> None:
    engine = RuleEngine(
        RulesConfig(
            burst_events=2,
            http_path_substrings=["/admin"],
            payload_keywords=["union select"],
            suppression_seconds=0,
        )
    )
    burst = engine.evaluate(
        _event("2.2.2.2", 8080, listener="smtp")
    ) + engine.evaluate(_event("2.2.2.2", 8080, listener="smtp"))
    assert any(a.rule == "burst" for a in burst)

    http_alerts = engine.evaluate(_event("3.3.3.3", 8080, listener="http_raw", data={"path": "/admin/login"}))
    assert any(a.rule == "http_paths" for a in http_alerts)

    kw_alerts = engine.evaluate(_event("4.4.4.4", 8080, message="UNION SELECT *"))
    assert any(a.rule == "payload_keywords" for a in kw_alerts)
