import asyncio
import time
from phantom.logger import ThreatEvent, ThreatLogger

class SSHTrap:
    def __init__(self, host: str = "0.0.0.0", port: int = 2222, logger: ThreatLogger = None):
        self.host = host
        self.port = port
        self.logger = logger or ThreatLogger()
        self.server = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = peer[0], peer[1]

        # Send authentic SSH banner
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(512), timeout=5.0)
            banner = data.decode(errors="ignore").strip()

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
            writer.close()
            await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"🕸️ [SSHTrap] Listening on {self.host}:{self.port}...")
