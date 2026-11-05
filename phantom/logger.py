import json
import time
from dataclasses import dataclass, asdict
from rich.console import Console

console = Console()

@dataclass
class ThreatEvent:
    timestamp: float
    service: str
    source_ip: str
    source_port: int
    event_type: str
    payload: str
    severity: str

class ThreatLogger:
    def __init__(self, log_path: str = "attacks.json"):
        self.log_path = log_path

    def record(self, event: ThreatEvent):
        color = "red" if event.severity in ["High", "Critical"] else "yellow"
        console.print(f"[{color}]🚨 [THREAT-{event.service.upper()}] {event.source_ip}:{event.source_port} -> {event.event_type} | {event.payload[:80]}[/{color}]")

        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception:
            pass
