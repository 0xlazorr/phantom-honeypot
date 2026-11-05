import argparse
import asyncio
from phantom.logger import ThreatLogger
from phantom.ssh_trap import SSHTrap
from phantom.redis_trap import RedisTrap
from phantom.http_trap import HttpTrap

async def run_traps(traps: list):
    logger = ThreatLogger()
    servers = []

    if "ssh" in traps:
        ssh = SSHTrap(port=2222, logger=logger)
        await ssh.start()
        servers.append(ssh.server)

    if "redis" in traps:
        redis_s = RedisTrap(port=6380, logger=logger)
        await redis_s.start()
        servers.append(redis_s.server)

    if "http" in traps:
        http_s = HttpTrap(port=8080, logger=logger)
        await http_s.start()
        servers.append(http_s.server)

    print("🚀 All honeypot deception traps activated. Press Ctrl+C to terminate.")
    try:
        await asyncio.gather(*[s.serve_forever() for s in servers])
    except asyncio.CancelledError:
        pass

def main():
    parser = argparse.ArgumentParser(description="Phantom Honeypot Sensor")
    subparsers = parser.add_subparsers(dest="command")

    start_p = subparsers.add_parser("start", help="Start deception traps")
    start_p.add_argument("--traps", default="ssh,redis,http", help="Comma-separated traps")

    args = parser.parse_args()
    if args.command == "start":
        trap_list = [t.strip().lower() for t in args.traps.split(",") if t.strip()]
        asyncio.run(run_traps(trap_list))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
