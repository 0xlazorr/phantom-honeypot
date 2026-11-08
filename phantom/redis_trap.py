import asyncio
from enum import Enum
import time
from phantom.logger import ThreatEvent, ThreatLogger

class RedisSessionState(str, Enum):
    CONNECTED = "CONNECTED"
    WAITING_COMMAND = "WAITING_COMMAND"
    COMMAND_RECEIVED = "COMMAND_RECEIVED"
    RESPONDED = "RESPONDED"
    TERMINATING = "TERMINATING"
    CLOSED = "CLOSED"

class TrapState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    LISTENING = "LISTENING"
    STOPPING = "STOPPING"

class RedisTrap:
    def __init__(self, host: str = "0.0.0.0", port: int = 6380, logger: ThreatLogger = None):
        self.host = host
        self.port = port
        self.logger = logger or ThreatLogger()
        self.server = None
        self.state = TrapState.STOPPED

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session_state = RedisSessionState.CONNECTED
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)

        while True:
            try:
                session_state = RedisSessionState.WAITING_COMMAND
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                if not line: break

                cmd = line.decode(errors="ignore").strip()
                if not cmd: continue

                session_state = RedisSessionState.COMMAND_RECEIVED
                severity = "Critical" if any(w in cmd.upper() for w in ["CONFIG", "SLAVEOF", "EVAL", "MODULE", "FLUSHALL"]) else "Medium"

                self.logger.record(ThreatEvent(
                    timestamp=time.time(),
                    service="redis",
                    source_ip=ip,
                    source_port=port,
                    event_type="MALICIOUS_REDIS_COMMAND",
                    payload=cmd,
                    severity=severity,
                ))

                # Respond with realistic Redis RESP protocol tokens
                if "PING" in cmd.upper():
                    writer.write(b"+PONG\r\n")
                elif "INFO" in cmd.upper():
                    writer.write(b"$55\r\n# Server\r\nredis_version:7.0.5\r\nos:Linux\r\ntcp_port:6379\r\n\r\n")
                else:
                    writer.write(b"+OK\r\n")
                await writer.drain()
                session_state = RedisSessionState.RESPONDED

            except Exception:
                break

        session_state = RedisSessionState.TERMINATING
        writer.close()
        await writer.wait_closed()
        session_state = RedisSessionState.CLOSED

    async def start(self):
        self.state = TrapState.STARTING
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.state = TrapState.LISTENING
        print(f"🕸️ [RedisTrap] Listening on {self.host}:{self.port}...")

    async def stop(self):
        if self.server:
            self.state = TrapState.STOPPING
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            self.state = TrapState.STOPPED
