import asyncio
from enum import Enum
import time
from phantom.logger import ThreatEvent, ThreatLogger

class SSHSessionState(str, Enum):
    CONNECTED = "CONNECTED"
    BANNER_SENT = "BANNER_SENT"
    CLIENT_IDENTIFIED = "CLIENT_IDENTIFIED"
    DISCONNECTING = "DISCONNECTING"
    CLOSED = "CLOSED"

class TrapState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    LISTENING = "LISTENING"
    STOPPING = "STOPPING"

class SSHTrap:
    def __init__(self, host: str = "0.0.0.0", port: int = 2222, logger: ThreatLogger = None):
        self.host = host
        self.port = port
        self.logger = logger or ThreatLogger()
        self.server = None
        self.state = TrapState.STOPPED

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session_state = SSHSessionState.CONNECTED
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)

        # Send authentic SSH banner
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        await writer.drain()
        session_state = SSHSessionState.BANNER_SENT

        try:
            data = await asyncio.wait_for(reader.read(512), timeout=5.0)
            banner = data.decode(errors="ignore").strip()
            session_state = SSHSessionState.CLIENT_IDENTIFIED

            self.logger.record(ThreatEvent(
                timestamp=time.time(),
                service="ssh",
                source_ip=ip,
                source_port=port,
                event_type="SSH_HANDSHAKE_ATTEMPT",
                payload=f"Client Banner: {banner}",
                severity="Medium",
            ))
        except Exception:
            pass
        finally:
            session_state = SSHSessionState.DISCONNECTING
            writer.close()
            await writer.wait_closed()
            session_state = SSHSessionState.CLOSED

    async def start(self):
        self.state = TrapState.STARTING
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.state = TrapState.LISTENING
        print(f"🕸️ [SSHTrap] Listening on {self.host}:{self.port}...")

    async def stop(self):
        if self.server:
            self.state = TrapState.STOPPING
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            self.state = TrapState.STOPPED
