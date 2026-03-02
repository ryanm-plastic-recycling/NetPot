from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from honeysentinel.alerting import Alert
from honeysentinel.config import RulesConfig
from honeysentinel.events import Event


@dataclass(slots=True)
class _State:
    timestamps: deque[tuple[datetime, Event]]


class RuleEngine:
    def __init__(self, cfg: RulesConfig) -> None:
        self.cfg = cfg
        self.events_by_ip: dict[str, _State] = defaultdict(lambda: _State(deque()))
        self.last_alert: dict[tuple[str, str], datetime] = {}

    def evaluate(self, event: Event) -> list[Alert]:
        now = datetime.now(timezone.utc)
        state = self.events_by_ip[event.src_ip]
        state.timestamps.append((now, event))

        max_window = max(self.cfg.portscan_window_seconds, self.cfg.burst_window_seconds)
        cutoff = now - timedelta(seconds=max_window)
        while state.timestamps and state.timestamps[0][0] < cutoff:
            state.timestamps.popleft()

        alerts: list[Alert] = []
        alerts.extend(self._portscan(event, now))
        alerts.extend(self._burst(event, now))
        alerts.extend(self._http_paths(event, now))
        alerts.extend(self._payload_keywords(event, now))
        return alerts

    def _should_alert(self, rule: str, src_ip: str, now: datetime) -> bool:
        key = (rule, src_ip)
        previous = self.last_alert.get(key)
        if previous and now - previous < timedelta(seconds=self.cfg.suppression_seconds):
            return False
        self.last_alert[key] = now
        return True

    def _portscan(self, event: Event, now: datetime) -> list[Alert]:
        cutoff = now - timedelta(seconds=self.cfg.portscan_window_seconds)
        ports = {
            existing.dst_port
            for ts, existing in self.events_by_ip[event.src_ip].timestamps
            if ts >= cutoff
        }
        if len(ports) >= self.cfg.portscan_distinct_ports and self._should_alert(
            "portscan", event.src_ip, now
        ):
            msg = f"{len(ports)} distinct destination ports in window"
            return [Alert("portscan", "high", event.src_ip, msg)]
        return []

    def _burst(self, event: Event, now: datetime) -> list[Alert]:
        cutoff = now - timedelta(seconds=self.cfg.burst_window_seconds)
        count = sum(
            1
            for ts, existing in self.events_by_ip[event.src_ip].timestamps
            if ts >= cutoff and existing.listener == event.listener
        )
        if count >= self.cfg.burst_events and self._should_alert(
            "burst", event.src_ip, now
        ):
            return [
                Alert(
                    "burst",
                    "medium",
                    event.src_ip,
                    f"{count} events on listener {event.listener}",
                )
            ]
        return []

    def _http_paths(self, event: Event, now: datetime) -> list[Alert]:
        path = str(event.data.get("path", "")).lower()
        if path and any(x.lower() in path for x in self.cfg.http_path_substrings):
            if self._should_alert("http_paths", event.src_ip, now):
                return [
                    Alert("http_paths", "medium", event.src_ip, f"Suspicious HTTP path {path}")
                ]
        return []

    def _payload_keywords(self, event: Event, now: datetime) -> list[Alert]:
        values = [
            event.message,
            event.data.get("line"),
            event.data.get("body_preview"),
            event.data.get("payload_preview"),
        ]
        haystack = " ".join(str(v).lower() for v in values if v)
        for keyword in self.cfg.payload_keywords:
            if keyword.lower() in haystack and self._should_alert(
                "payload_keywords", event.src_ip, now
            ):
                return [
                    Alert(
                        "payload_keywords",
                        "high",
                        event.src_ip,
                        f"Keyword matched: {keyword}",
                    )
                ]
        return []
