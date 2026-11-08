import asyncio
from enum import Enum
import time
from phantom.logger import ThreatEvent, ThreatLogger

class HttpSessionState(str, Enum):
    CONNECTED = "CONNECTED"
    WAITING_REQUEST_LINE = "WAITING_REQUEST_LINE"
    READING_HEADERS = "READING_HEADERS"
    SENDING_RESPONSE = "SENDING_RESPONSE"
    TERMINATING = "TERMINATING"
    CLOSED = "CLOSED"

class TrapState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    LISTENING = "LISTENING"
    STOPPING = "STOPPING"

class HttpTrap:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, logger: ThreatLogger = None):
        self.host = host
        self.port = port
        self.logger = logger or ThreatLogger()
        self.server = None
        self.state = TrapState.STOPPED

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session_state = HttpSessionState.CONNECTED
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)

        try:
            session_state = HttpSessionState.WAITING_REQUEST_LINE
            req_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            first_line = req_line.decode(errors="ignore").strip()

            session_state = HttpSessionState.READING_HEADERS
            headers = []
            while True:
                line = await reader.readline()
                if line in [b"\r\n", b"\n", b""]: break
                headers.append(line.decode(errors="ignore").strip())

            full_payload = first_line + " | " + " ".join(headers[:3])

            severity = "High" if any(s in full_payload.lower() for s in [".env", ".git", "jndi:", "select ", "etc/passwd", "cmd="]) else "Low"

            self.logger.record(ThreatEvent(
                timestamp=time.time(),
                service="http",
                source_ip=ip,
                source_port=port,
                event_type="SUSPICIOUS_WEB_SCAN",
                payload=full_payload,
                severity=severity,
            ))

            # Send 404 or 401 response
            session_state = HttpSessionState.SENDING_RESPONSE
            response = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nNot Found"
            writer.write(response)
            await writer.drain()
        except Exception:
            pass
        finally:
            session_state = HttpSessionState.TERMINATING
            writer.close()
            await writer.wait_closed()
            session_state = HttpSessionState.CLOSED

    async def start(self):
        self.state = TrapState.STARTING
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.state = TrapState.LISTENING
        print(f"🕸️ [HttpTrap] Listening on {self.host}:{self.port}...")

    async def stop(self):
        if self.server:
            self.state = TrapState.STOPPING
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            self.state = TrapState.STOPPED
