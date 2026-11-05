import asyncio
from phantom.logger import ThreatLogger
from phantom.ssh_trap import SSHTrap
from phantom.redis_trap import RedisTrap
from phantom.http_trap import HttpTrap

async def main():
    print("🕸️ Starting Phantom Honeypot Test...")
    logger = ThreatLogger()

    ssh = SSHTrap(port=2222, logger=logger)
    redis_t = RedisTrap(port=6380, logger=logger)
    http_t = HttpTrap(port=8080, logger=logger)

    await ssh.start()
    await redis_t.start()
    await http_t.start()

    print("✅ All honeypot services active. Running for 5 seconds...")
    await asyncio.sleep(5)
    print("Demo complete.")

if __name__ == "__main__":
    asyncio.run(main())
