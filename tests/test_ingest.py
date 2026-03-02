from honeysentinel.ingest import parse_suricata_eve_line, parse_zeek_conn_line


def test_parse_suricata_eve_line() -> None:
    line = (
        '{"timestamp":"2025-01-01T00:00:00.000000+0000","event_type":"alert",'
        '"src_ip":"10.0.0.10","dest_ip":"10.0.0.5","src_port":44444,'
        '"dest_port":22,"proto":"TCP","alert":{"signature":"ET Scan"}}'
    )
    event = parse_suricata_eve_line(line)
    assert event is not None
    assert event.event_type == "suricata_eve"
    assert event.src_ip == "10.0.0.10"
    assert event.dst_port == 22
    assert event.data["signature"] == "ET Scan"


def test_parse_zeek_conn_line() -> None:
    line = (
        '{"ts":1735689600.0,"uid":"C1","id.orig_h":"10.0.0.20","id.orig_p":51322,'
        '"id.resp_p":443,"proto":"tcp","service":"ssl","duration":1.2,'
        '"orig_bytes":120,"resp_bytes":456}'
    )
    event = parse_zeek_conn_line(line)
    assert event is not None
    assert event.event_type == "zeek_conn"
    assert event.src_ip == "10.0.0.20"
    assert event.src_port == 51322
    assert event.dst_port == 443
    assert event.data["service"] == "ssl"
